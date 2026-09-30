using System.Formats.Cbor;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.Passkeys;

internal sealed class PasskeyService(
    IFido2 fido2,
    IPasskeyCredentialStore credentials,
    IPasskeyChallengeStore challenges,
    IUserStore users,
    LocalSessionIssuer sessions,
    TwoFactorGate twoFactor,
    AuthenticationEventPublisher events,
    ToamaisutaaMetrics metrics,
    IOptions<ToamaisutaaPasskeyOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin,
    TimeProvider timeProvider,
    IServiceProvider provider,
    ILogger<PasskeyService> logger) : IPasskeyService
{
    public async Task<PasskeyCeremonyStarted> BeginRegistrationAsync(
        Guid userId,
        PasskeyRegistrationProof proof,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proof);

        var settings = options.Value;

        var user = await users.FindByIdAsync(userId, cancellationToken)
            ?? throw new InvalidOperationException($"User {userId} does not exist.");

        await RequireLiveCredentialAsync(userId, proof, Registration, timeProvider.GetUtcNow(), cancellationToken);

        var existing = await credentials.ListAsync(userId, cancellationToken);

        if (settings.MaxCredentialsPerUser > 0 && existing.Count >= settings.MaxCredentialsPerUser)
        {
            throw new PasskeyRegistrationException(
                $"This account already has {existing.Count} passkeys, which is the configured maximum. "
                + "Delete one before registering another.");
        }

        var created = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            // The user handle is the id, never a name: it is shown in account pickers on shared
            // machines, so an email address here would leak.
            User = new Fido2User
            {
                Id = userId.ToByteArray(),
                Name = user.UserName ?? user.Email ?? userId.ToString(),
                DisplayName = user.DisplayName ?? user.UserName ?? user.Email ?? userId.ToString(),
            },

            // Stops an authenticator quietly making a second, indistinguishable credential for this account.
            ExcludeCredentials = [.. existing.Select(credential => new PublicKeyCredentialDescriptor(credential.CredentialId))],

            AuthenticatorSelection = new AuthenticatorSelection
            {
                // Required, not configurable: sign-in begins with no identifier, so a non-discoverable
                // credential would register and then never appear at a sign-in prompt.
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = settings.RequireUserVerification
                    ? UserVerificationRequirement.Required
                    : UserVerificationRequirement.Preferred,
            },

            // Nothing checks attestation, so asking for it would only disclose the authenticator's model.
            AttestationPreference = AttestationConveyancePreference.None,
        });

        return await StoreChallengeAsync(userId, created.ToJson(), PasskeyCeremony.Registration, cancellationToken);
    }

    public async Task<PasskeySummary> CompleteRegistrationAsync(
        Guid userId,
        PasskeyRegistrationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();
        var stored = await RedeemAsync(request.Challenge, PasskeyCeremony.Registration, now, cancellationToken);

        if (stored is null || stored.UserId != userId)
            throw new PasskeyRegistrationException("That registration has expired or was already finished. Start another.");

        RegisteredPublicKeyCredential registered;

        try
        {
            registered = await fido2.MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = new AuthenticatorAttestationRawResponse
                    {
                        Id = request.Id,
                        RawId = PasskeyEncoding.Decode(request.Id),
                        Type = PublicKeyCredentialType.PublicKey,
                        Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                        {
                            AttestationObject = PasskeyEncoding.Decode(request.AttestationObject),
                            ClientDataJson = PasskeyEncoding.Decode(request.ClientDataJson),
                            Transports = ParseTransports(request.Transports),
                        },
                    },
                    OriginalOptions = CredentialCreateOptions.FromJson(stored.Options),
                    IsCredentialIdUniqueToUserCallback = async (parameters, token) =>
                        await credentials.FindByCredentialIdAsync(parameters.CredentialId, token) is null,
                },
                cancellationToken);
        }
        catch (Fido2VerificationException exception)
        {
            // Returning the library's message is safe: the reader is signed in and registering their own authenticator.
            logger.LogWarning(
                exception,
                "Passkey registration refused for user {UserId}: {Code}.",
                userId,
                exception.Code);

            throw new PasskeyRegistrationException($"That passkey could not be verified: {exception.Message}");
        }
        catch (FormatException)
        {
            throw new PasskeyRegistrationException("That passkey could not be read. The response fields must be base64url.");
        }

        if (registered.Id.Length > 256)
        {
            // Refused rather than truncated: sign-in matches on the full id, so a shortened one could never be used.
            throw new PasskeyRegistrationException(
                $"That authenticator produced a {registered.Id.Length}-byte credential id, and this package stores at "
                + "most 256. Register a different authenticator.");
        }

        var credential = new ToamaisutaaPasskeyCredential
        {
            Id = Guid.CreateVersion7(now),
            UserId = userId,
            CredentialId = registered.Id,
            PublicKey = registered.PublicKey,
            SignCount = registered.SignCount,
            AaGuid = registered.AaGuid,
            Transports = Describe(registered.Transports),
            AttestationFormat = registered.AttestationFormat,
            IsBackupEligible = registered.IsBackupEligible,
            IsBackedUp = registered.IsBackedUp,
            Label = ClientMetadata.Truncate(request.Label, 128),
            CreatedAt = now,
        };

        await credentials.CreateAsync(credential, cancellationToken);

        await events.PublishAsync(
            new PasskeyRegistered
            {
                OccurredAt = now,
                UserId = userId,
                PasskeyId = credential.Id,
                Label = credential.Label,
            },
            cancellationToken);

        logger.LogInformation("Registered passkey {PasskeyId} for user {UserId}.", credential.Id, userId);

        return Summarise(credential);
    }

    public async Task<PasskeyCeremonyStarted> BeginAssertionAsync(CancellationToken cancellationToken = default)
    {
        // No allowed credentials: a per-identifier list would tell an anonymous caller whether an account exists.
        var assertion = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = options.Value.RequireUserVerification
                ? UserVerificationRequirement.Required
                : UserVerificationRequirement.Preferred,
        });

        return await StoreChallengeAsync(userId: null, assertion.ToJson(), PasskeyCeremony.Assertion, cancellationToken);
    }

    public async Task<PasskeySignInResult> CompleteAssertionAsync(
        PasskeyAssertionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();
        var stored = await RedeemAsync(request.Challenge, PasskeyCeremony.Assertion, now, cancellationToken);

        if (stored is null)
            return await RefusedAsync(SignInOutcome.InvalidChallenge, userId: null, now, cancellationToken);

        byte[] credentialId;

        try
        {
            credentialId = PasskeyEncoding.Decode(request.Id);
        }
        catch (FormatException)
        {
            return await RefusedAsync(SignInOutcome.InvalidPasskey, userId: null, now, cancellationToken);
        }

        var credential = await credentials.FindByCredentialIdAsync(credentialId, cancellationToken);

        if (credential is null)
        {
            logger.LogWarning("Passkey sign-in refused: no credential matches the id presented.");
            return await RefusedAsync(SignInOutcome.InvalidPasskey, userId: null, now, cancellationToken);
        }

        VerifyAssertionResult verified;
        byte[] rawAuthenticatorData;

        try
        {
            rawAuthenticatorData = PasskeyEncoding.Decode(request.AuthenticatorData);

            verified = await fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = new AuthenticatorAssertionRawResponse
                    {
                        Id = request.Id,
                        RawId = credentialId,
                        Type = PublicKeyCredentialType.PublicKey,
                        Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                        {
                            AuthenticatorData = rawAuthenticatorData,
                            ClientDataJson = PasskeyEncoding.Decode(request.ClientDataJson),
                            Signature = PasskeyEncoding.Decode(request.Signature),
                            UserHandle = request.UserHandle is null ? null : PasskeyEncoding.Decode(request.UserHandle),
                        },
                    },
                    OriginalOptions = AssertionOptions.FromJson(stored.Options),
                    StoredPublicKey = credential.PublicKey,

                    // A counter that fails to advance past this betrays a cloned authenticator.
                    StoredSignatureCounter = (uint)credential.SignCount,

                    IsUserHandleOwnerOfCredentialIdCallback = (parameters, _) =>
                        Task.FromResult(OwnsCredential(parameters.UserHandle, credential)),
                },
                cancellationToken);
        }
        catch (Fido2VerificationException exception)
        {
            logger.LogWarning(
                "Passkey sign-in refused for user {UserId}: {Code}.",
                credential.UserId,
                exception.Code);

            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }
        catch (FormatException)
        {
            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }
        catch (CborContentException)
        {
            // The library throws this for an extension flag with no CBOR behind it; without the catch
            // an anonymous endpoint answers 500 to a malformed field.
            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken);

        if (user is null)
        {
            logger.LogError(
                "Passkey {PasskeyId} points at user {UserId}, which does not exist.",
                credential.Id,
                credential.UserId);

            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        // After the stamp is read: every revocation deletes passkeys before it moves the stamp, so a
        // credential still here means the stamp read is one the revocation has yet to kill.
        if (await credentials.FindByCredentialIdAsync(credentialId, cancellationToken) is null)
        {
            logger.LogWarning("Passkey sign-in refused for user {UserId}: the passkey was removed while it was being checked.", credential.UserId);
            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        await credentials.RecordUseAsync(credential.Id, verified.SignCount, verified.IsBackedUp, now, cancellationToken);

        metrics.TwoFactorVerified(TwoFactorSource.Passkey, succeeded: true);

        // Read off the raw bytes only after the library has verified them, since parsing unchecked bytes
        // can throw CBOR errors. Byte 32 is the flags byte and 0x04 is UV, both fixed by the specification.
        var userVerified = (rawAuthenticatorData[32] & (byte)AuthenticatorFlags.UV) != 0;

        // An assertion without user verification is possession alone, so an enrolled account still
        // gets a second-factor challenge; otherwise a borrowed security key would beat its policy.
        if (!userVerified && await twoFactor.RequiresChallengeAsync(user.Id, cancellationToken))
        {
            var challenge = await twoFactor.IssueChallengeAsync(
                user.Id,
                now,
                cancellationToken,
                authenticationMethods: $"{ToamaisutaaDefaults.HardwareKeyMethod} {ToamaisutaaDefaults.UserPresenceMethod}");

            logger.LogInformation(
                "Passkey accepted for user {UserId} without user verification; a second factor is required.",
                user.Id);

            metrics.SignInCompleted(SignInOutcome.TwoFactorRequired, methods: null);

            return new PasskeySignInResult { Outcome = SignInOutcome.TwoFactorRequired, Challenge = challenge };
        }

        // hwk and user are RFC 8176. mfa only when the authenticator verified the user, because the
        // enrolment policy reads it as the second factor.
        List<string> methods = userVerified
            ? [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod, ToamaisutaaDefaults.MultiFactorMethod]
            : [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod];

        var issued = await sessions.IssueAsync(
            new LocalSessionRequest
            {
                User = user,
                Methods = methods,

                // Carried onto the refresh row, so a refreshed token still satisfies the policies it did at sign-in.
                TwoFactorSource = userVerified ? TwoFactorSource.Passkey : null,
                SecondFactorAt = userVerified ? now : null,

                NewSignIn = true,
                Client = ClientMetadata.Describe(request.UserAgent, request.IpAddress, localLogin.Value.IpAddressStorage),
                Now = now,
            },
            cancellationToken);

        logger.LogInformation(
            "Sign-in succeeded for user {UserId} with passkey {PasskeyId}{Verified}.",
            user.Id,
            credential.Id,
            userVerified ? " and user verification" : " without user verification");

        metrics.SignInCompleted(SignInOutcome.Succeeded, methods);

        return new PasskeySignInResult { Outcome = SignInOutcome.Succeeded, Tokens = issued.Tokens };
    }

    public async Task<IReadOnlyList<PasskeySummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default) =>
        [.. (await credentials.ListAsync(userId, cancellationToken)).Select(Summarise)];

    public async Task<bool> DeleteAsync(
        Guid userId,
        Guid passkeyId,
        PasskeyRegistrationProof proof,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proof);

        var now = timeProvider.GetUtcNow();

        // Checked first so the answer is the same whether or not the id is this account's.
        await RequireLiveCredentialAsync(userId, proof, Removal, now, cancellationToken);

        if (!await credentials.DeleteAsync(userId, passkeyId, cancellationToken))
            return false;

        // Nothing records which session this key opened, so all of them end.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await provider.GetRequiredService<IRefreshTokenStore>().RevokeAllForUserAsync(userId, "passkey-removed", now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked { OccurredAt = now, UserId = userId, Reason = "passkey-removed" },
            cancellationToken);

        await events.PublishAsync(
            new PasskeyRemoved { OccurredAt = now, UserId = userId, PasskeyId = passkeyId },
            cancellationToken);

        // A warning because on a passwordless account this may have removed the last way in.
        var remaining = await credentials.CountAsync(userId, cancellationToken);

        logger.LogWarning(
            "Deleted passkey {PasskeyId} for user {UserId}. {Remaining} passkey(s) remain on the account.",
            passkeyId,
            userId,
            remaining);

        return true;
    }

    // A passkey signs in on its own, so registering one on an account with a second factor takes that
    // second factor: the password alone would mint a way in that skips it. Removing one gives nothing.
    private readonly record struct ProvenOperation(string Name, string Doing, string Retry, bool NeedsSecondFactorWhenEnrolled);

    private static readonly ProvenOperation Registration = new("Passkey registration", "Registering a passkey", "register", NeedsSecondFactorWhenEnrolled: true);

    private static readonly ProvenOperation Removal = new("Passkey removal", "Removing a passkey", "remove it", NeedsSecondFactorWhenEnrolled: false);

    private async Task RequireLiveCredentialAsync(
        Guid userId,
        PasskeyRegistrationProof proof,
        ProvenOperation operation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var window = options.Value.RegistrationProofWindow;

        // A time ahead of now is refused so a skewed issuer clock cannot extend the window.
        if (proof.SecondFactorAt is { } presentedAt && presentedAt <= now && now - presentedAt <= window)
            return;

        if (operation.NeedsSecondFactorWhenEnrolled
            && provider.GetService<ITwoFactorStore>() is { } enrolments
            && await enrolments.FindAsync(userId, cancellationToken) is { ConfirmedAt: not null })
        {
            logger.LogWarning(
                "{Operation} refused for user {UserId}: the account has a second factor, and none was presented recently.",
                operation.Name,
                userId);

            throw new PasskeyRegistrationException(
                $"This account has a second factor, so {operation.Doing.ToLowerInvariant()} needs it too, not only the "
                + $"password. Complete a step-up, then {operation.Retry} while it is still fresh.");
        }

        // Resolved rather than injected: the password stores may not be registered, and passwordless
        // accounts prove a second factor instead.
        var passwords = provider.GetService<IPasswordCredentialStore>();
        var credential = passwords is null ? null : await passwords.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            logger.LogWarning(
                "{Operation} refused for user {UserId}: the account has no password, and no second factor was presented recently.",
                operation.Name,
                userId);

            throw new PasskeyRegistrationException(
                $"This account has no password to prove, so {operation.Doing.ToLowerInvariant()} needs a second factor. "
                + $"Complete a step-up, then {operation.Retry} while it is still fresh.");
        }

        var hasher = provider.GetService<IPasswordHasher>();

        if (hasher is null || string.IsNullOrEmpty(proof.CurrentPassword))
        {
            logger.LogWarning("{Operation} refused for user {UserId}: no current password was given.", operation.Name, userId);

            throw new PasskeyRegistrationException(
                $"{operation.Doing} needs proof of a credential this account already has. Send currentPassword, or "
                + $"complete a step-up, then {operation.Retry} while it is still fresh.");
        }

        // Counted exactly as a wrong password at sign-in is: a stolen access token reaches this.
        var refusal = await passwords!.CheckCurrentPasswordAsync(
            credential,
            proof.CurrentPassword,
            hasher,
            events,
            localLogin.Value,
            logger,
            operation.Name,
            now,
            cancellationToken);

        if (refusal is not null)
            throw new PasskeyRegistrationException(refusal);
    }

    /// <summary>
    /// Stores the options server-side rather than round-tripping them, since a client that could return
    /// them could loosen the rules the completion step checks against.
    /// </summary>
    private async Task<PasskeyCeremonyStarted> StoreChallengeAsync(
        Guid? userId,
        string optionsJson,
        PasskeyCeremony ceremony,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var lifetime = options.Value.ChallengeLifetime;
        var raw = SecureTokens.Create();

        await challenges.CreateAsync(
            new ToamaisutaaPasskeyChallenge
            {
                Id = Guid.CreateVersion7(now),
                UserId = userId,
                TokenHash = SecureTokens.HashToken(raw),
                Options = optionsJson,
                Ceremony = ceremony,
                CreatedAt = now,
                ExpiresAt = now + lifetime,
            },
            cancellationToken);

        return new PasskeyCeremonyStarted
        {
            Challenge = raw,
            ExpiresIn = (int)lifetime.TotalSeconds,
            Options = JsonDocument.Parse(optionsJson).RootElement.Clone(),
        };
    }

    /// <summary>
    /// Consumed before the ceremony is verified, unlike the two-factor challenge: a failed authenticator
    /// response is not a typo, and a live challenge would allow unlimited attempts against it.
    /// </summary>
    private async Task<ToamaisutaaPasskeyChallenge?> RedeemAsync(
        string token,
        PasskeyCeremony ceremony,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        var stored = await challenges.FindByHashAsync(SecureTokens.HashToken(token), cancellationToken);

        if (stored is null)
            return null;

        if (stored.Ceremony != ceremony)
        {
            logger.LogWarning(
                "Passkey challenge was presented at the wrong endpoint: it is a {Actual} challenge and this is {Expected}.",
                stored.Ceremony,
                ceremony);

            return null;
        }

        if (stored.ConsumedAt is not null)
        {
            logger.LogWarning("Passkey challenge was presented again after being spent.");
            return null;
        }

        if (stored.ExpiresAt <= now)
            return null;

        // Only the winner of the write proceeds: a synced passkey reports a counter of zero, so clone
        // detection cannot catch two assertions over one challenge.
        if (!await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Passkey challenge was spent by another request first.");
            return null;
        }

        return stored;
    }

    private async Task<PasskeySignInResult> RefusedAsync(
        SignInOutcome outcome,
        Guid? userId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (outcome == SignInOutcome.InvalidPasskey)
            metrics.TwoFactorVerified(TwoFactorSource.Passkey, succeeded: false);

        metrics.SignInCompleted(outcome, methods: null);

        await events.PublishAsync(
            new SignInFailed { OccurredAt = now, UserId = userId, Reason = outcome },
            cancellationToken);

        return new PasskeySignInResult { Outcome = outcome };
    }

    /// <summary>
    /// A handle that does not parse as a user id is refused rather than ignored, since it may be one
    /// credential's response substituted for another's.
    /// </summary>
    private static bool OwnsCredential(byte[]? userHandle, ToamaisutaaPasskeyCredential credential) =>
        userHandle is { Length: 16 } && new Guid(userHandle) == credential.UserId;

    private static PasskeySummary Summarise(ToamaisutaaPasskeyCredential credential) => new()
    {
        Id = credential.Id,
        Label = credential.Label,
        Transports = credential.Transports is null ? [] : credential.Transports.Split(' '),
        IsBackedUp = credential.IsBackedUp,
        CreatedAt = credential.CreatedAt,
        LastUsedAt = credential.LastUsedAt,
    };

    /// <summary>
    /// Unknown transports are dropped rather than refused: the list is only a prompt hint and nothing
    /// authorises on it.
    /// </summary>
    private static AuthenticatorTransport[] ParseTransports(IReadOnlyList<string>? transports)
    {
        if (transports is null)
            return [];

        var parsed = new List<AuthenticatorTransport>(transports.Count);

        foreach (var transport in transports)
        {
            if (Enum.TryParse<AuthenticatorTransport>(transport, ignoreCase: true, out var value))
                parsed.Add(value);
        }

        return [.. parsed];
    }

    private static string? Describe(AuthenticatorTransport[]? transports) =>
        transports is null or { Length: 0 }
            ? null
            : string.Join(' ', transports.Select(transport => transport.ToString().ToLowerInvariant()));
}
