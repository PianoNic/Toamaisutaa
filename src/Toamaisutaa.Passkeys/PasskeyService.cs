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
        CancellationToken cancellationToken = default) =>
        await CompleteRegistrationAsync(
            userId,
            (await users.FindByIdAsync(userId, cancellationToken))?.SecurityStamp,
            request,
            cancellationToken);

    public Task<PasskeySummary> CompleteRegistrationAsync(
        ToamaisutaaUser user,
        PasskeyRegistrationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        return CompleteRegistrationAsync(user.Id, user.SecurityStamp, request, cancellationToken);
    }

    private async Task<PasskeySummary> CompleteRegistrationAsync(
        Guid userId,
        string? stampAtStart,
        PasskeyRegistrationRequest request,
        CancellationToken cancellationToken)
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

        // A credential change that finished while this was verifying already deleted every passkey,
        // and missed this one; it would sign in on its own after the owner locked everyone out.
        if (!string.Equals(await users.ReadSecurityStampAsync(userId, cancellationToken), stampAtStart, StringComparison.Ordinal))
        {
            await credentials.DeleteAsync(userId, credential.Id, cancellationToken);

            logger.LogWarning("Passkey registration refused for user {UserId}: the account's credentials changed while it was being registered.", userId);

            throw new PasskeyRegistrationException(
                "Your account's credentials changed while this passkey was being registered, so it was not kept. Sign in again and register it.");
        }

        // Counted again now it is in: the check at begin cannot see ceremonies begun alongside it,
        // each of which would otherwise add one past the maximum.
        var maximum = options.Value.MaxCredentialsPerUser;

        if (maximum > 0 && await credentials.CountAsync(userId, cancellationToken) > maximum)
        {
            await credentials.DeleteAsync(userId, credential.Id, cancellationToken);

            logger.LogWarning("Passkey registration refused for user {UserId}: the account would hold more than {Maximum} passkeys.", userId, maximum);

            throw new PasskeyRegistrationException(
                $"This account already has the configured maximum of {maximum} passkeys. Delete one before registering another.");
        }

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

        if (await VerifyAssertionAsync(stored, request, credential, credentialId, "Passkey sign-in", cancellationToken) is not { } checkedAssertion)
            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);

        var (verified, rawAuthenticatorData) = checkedAssertion;

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken);

        if (user is null)
        {
            logger.LogError(
                "Passkey {PasskeyId} points at user {UserId}, which does not exist.",
                credential.Id,
                credential.UserId);

            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        if (user.DisabledAt is not null)
        {
            logger.LogWarning("Passkey sign-in refused for user {UserId}: the account is disabled.", user.Id);
            return await RefusedAsync(SignInOutcome.AccountDisabled, user.Id, now, cancellationToken);
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

        // An assertion without user verification is possession alone, so an account with a TOTP
        // enrolment still gets a code challenge; otherwise a borrowed security key would beat its
        // policy. A code only, because answering with a passkey would be possession twice.
        if (!userVerified && await twoFactor.HasTotpAsync(user.Id, cancellationToken))
        {
            var challenge = await twoFactor.IssueChallengeAsync(
                user.Id,
                now,
                cancellationToken,
                authenticationMethods: $"{ToamaisutaaDefaults.HardwareKeyMethod} {ToamaisutaaDefaults.UserPresenceMethod}",

                // The stamp read before the credential was found again; read later, it can be the
                // stamp of the revocation that just deleted this passkey.
                securityStamp: user.SecurityStamp);

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

    public async Task<PasskeyCeremonyStarted?> BeginSecondFactorAsync(string signInChallenge, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        if (await twoFactor.FindLiveSignInChallengeAsync(signInChallenge, now, cancellationToken) is not { } userId)
            return null;

        var owned = await credentials.ListAsync(userId, cancellationToken);

        if (owned.Count == 0)
            return null;

        var assertion = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [.. owned.Select(credential => new PublicKeyCredentialDescriptor(credential.CredentialId))],
            UserVerification = options.Value.RequireUserVerification
                ? UserVerificationRequirement.Required
                : UserVerificationRequirement.Preferred,
        });

        return await StoreChallengeAsync(userId, assertion.ToJson(), PasskeyCeremony.SecondFactor, cancellationToken);
    }

    public async Task<PasskeySignInResult> CompleteSecondFactorAsync(PasskeySecondFactorRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Assertion);

        var now = timeProvider.GetUtcNow();
        var assertion = request.Assertion;
        var stored = await RedeemAsync(assertion.Challenge, PasskeyCeremony.SecondFactor, now, cancellationToken);

        if (stored?.UserId is not { } userId)
            return await RefusedAsync(SignInOutcome.InvalidChallenge, userId: null, now, cancellationToken);

        byte[] credentialId;

        try
        {
            credentialId = PasskeyEncoding.Decode(assertion.Id);
        }
        catch (FormatException)
        {
            return await RefusedAsync(SignInOutcome.InvalidPasskey, userId, now, cancellationToken);
        }

        // Only this account's own passkey answers its challenge.
        if (await credentials.FindByCredentialIdAsync(credentialId, cancellationToken) is not { } credential || credential.UserId != userId)
        {
            logger.LogWarning("Passkey second factor refused for user {UserId}: the passkey presented is not one of the account's.", userId);
            return await RefusedAsync(SignInOutcome.InvalidPasskey, userId, now, cancellationToken);
        }

        if (await VerifyAssertionAsync(stored, assertion, credential, credentialId, "Passkey second factor", cancellationToken) is not { } checkedAssertion)
            return await RefusedAsync(SignInOutcome.InvalidPasskey, userId, now, cancellationToken);

        var redemption = await twoFactor.RedeemWithPasskeyAsync(request.SignInChallenge, userId, now, cancellationToken);

        if (redemption.Outcome != SignInOutcome.Succeeded)
        {
            logger.LogWarning("Passkey second factor refused for user {UserId}: the sign-in challenge is {Outcome}.", userId, redemption.Outcome);
            return await RefusedAsync(redemption.Outcome, userId, now, cancellationToken);
        }

        var user = await users.FindByIdAsync(userId, cancellationToken);

        if (user is null || user.DisabledAt is not null)
        {
            logger.LogWarning("Passkey second factor refused for user {UserId}: the account is gone or disabled.", userId);
            return await RefusedAsync(SignInOutcome.AccountDisabled, userId, now, cancellationToken);
        }

        await credentials.RecordUseAsync(credential.Id, checkedAssertion.Verified.SignCount, checkedAssertion.Verified.IsBackedUp, now, cancellationToken);
        metrics.TwoFactorVerified(TwoFactorSource.Passkey, succeeded: true);

        // A finished sign-in clears the wrong-code count, exactly as a right code does.
        if (provider.GetService<IPasswordCredentialStore>() is { } passwords
            && await passwords.FindByUserIdAsync(userId, cancellationToken) is { } password)
        {
            await passwords.RegisterSuccessAsync(password, now, cancellationToken);
        }

        // The first factor comes off the challenge: a password, or a mailbox.
        List<string> methods =
        [
            .. string.IsNullOrEmpty(redemption.AuthenticationMethods) ? ["pwd"] : redemption.AuthenticationMethods.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            ToamaisutaaDefaults.HardwareKeyMethod,
            ToamaisutaaDefaults.MultiFactorMethod,
        ];

        var issued = await sessions.IssueAsync(
            new LocalSessionRequest
            {
                User = user,
                Methods = methods,
                TwoFactorSource = TwoFactorSource.Passkey,
                SecondFactorAt = now,
                NewSignIn = true,
                Client = ClientMetadata.Describe(assertion.UserAgent, assertion.IpAddress, localLogin.Value.IpAddressStorage),
                Now = now,
            },
            cancellationToken);

        logger.LogInformation("Sign-in completed for user {UserId} with passkey {PasskeyId} as the second factor.", userId, credential.Id);
        metrics.SignInCompleted(SignInOutcome.Succeeded, methods);

        return new PasskeySignInResult { Outcome = SignInOutcome.Succeeded, Tokens = issued.Tokens };
    }

    /// <summary>
    /// The one place an assertion is checked against a stored credential, so sign-in and a passkey
    /// second factor cannot drift into different rules. Null when it does not verify.
    /// </summary>
    private async Task<(VerifyAssertionResult Verified, byte[] AuthenticatorData)?> VerifyAssertionAsync(
        ToamaisutaaPasskeyChallenge stored,
        PasskeyAssertionRequest request,
        ToamaisutaaPasskeyCredential credential,
        byte[] credentialId,
        string ceremony,
        CancellationToken cancellationToken)
    {
        try
        {
            var rawAuthenticatorData = PasskeyEncoding.Decode(request.AuthenticatorData);

            var verified = await fido2.MakeAssertionAsync(
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

            return (verified, rawAuthenticatorData);
        }
        catch (Fido2VerificationException exception)
        {
            logger.LogWarning("{Ceremony} refused for user {UserId}: {Code}.", ceremony, credential.UserId, exception.Code);
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
        catch (CborContentException)
        {
            // The library throws this for an extension flag with no CBOR behind it; without the catch
            // an anonymous endpoint answers 500 to a malformed field.
            return null;
        }
        catch (ArgumentException)
        {
            // And this for a signature that is not well-formed DER, which is also just a bad field.
            return null;
        }
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
            metrics,
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
