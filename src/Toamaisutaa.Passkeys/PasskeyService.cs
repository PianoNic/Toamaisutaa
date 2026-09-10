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

        await RequireLiveCredentialAsync(userId, proof, timeProvider.GetUtcNow(), cancellationToken);

        var existing = await credentials.ListAsync(userId, cancellationToken);

        if (settings.MaxCredentialsPerUser > 0 && existing.Count >= settings.MaxCredentialsPerUser)
        {
            throw new PasskeyRegistrationException(
                $"This account already has {existing.Count} passkeys, which is the configured maximum. "
                + "Delete one before registering another.");
        }

        var created = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            // The user id, and nothing derived from a name. A user handle is stored on the
            // authenticator and shown in account pickers on shared machines, so an email address
            // here would leak one to whoever borrows the laptop.
            User = new Fido2User
            {
                Id = userId.ToByteArray(),
                Name = user.UserName ?? user.Email ?? userId.ToString(),
                DisplayName = user.DisplayName ?? user.UserName ?? user.Email ?? userId.ToString(),
            },

            // So an authenticator that already holds a credential for this account says so rather
            // than quietly making a second one the user will never be able to tell apart.
            ExcludeCredentials = [.. existing.Select(credential => new PublicKeyCredentialDescriptor(credential.CredentialId))],

            AuthenticatorSelection = new AuthenticatorSelection
            {
                // Required rather than configurable. Sign-in here begins with no identifier, so
                // the browser has to be able to find the credential on its own; a non-discoverable
                // one would register happily and then never appear at a sign-in prompt again.
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = settings.RequireUserVerification
                    ? UserVerificationRequirement.Required
                    : UserVerificationRequirement.Preferred,
            },

            // Nothing here inspects an attestation statement, and asking for one that is never
            // checked buys nothing while sending the authenticator's model to the server.
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
            // The message names the check that failed - a wrong origin, an attestation that does not
            // parse - and the person reading it is signed in and registering their own authenticator,
            // so there is nobody here to tell something they did not already know.
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
            // Refused rather than truncated. The credential id is what the sign-in path matches on,
            // so a shortened one is a credential that registers and can never be used again.
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
        // No allowed credentials, because there is no identifier: the browser finds a discoverable
        // credential itself. It is also what keeps this endpoint from answering "does this account
        // exist" to an anonymous caller, which a per-identifier list would do by its length alone.
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

                    // The counter the authenticator last reported. A value that fails to advance is
                    // how a cloned authenticator gives itself away, and the library refuses it.
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
            // Authenticator data whose extension flag is set with no CBOR behind it. The library
            // parses that before it validates anything, and what comes out is neither of the two
            // above - so without this an anonymous endpoint answers 500 to a malformed field.
            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken);

        if (user is null)
        {
            // A credential outliving its user row is a broken cascade rather than a failed sign-in,
            // so it is logged as the fault it is instead of being counted as an attempt.
            logger.LogError(
                "Passkey {PasskeyId} points at user {UserId}, which does not exist.",
                credential.Id,
                credential.UserId);

            return await RefusedAsync(SignInOutcome.InvalidPasskey, credential.UserId, now, cancellationToken);
        }

        await credentials.RecordUseAsync(credential.Id, verified.SignCount, verified.IsBackedUp, now, cancellationToken);

        metrics.TwoFactorVerified(TwoFactorSource.Passkey, succeeded: true);

        // Read off the raw bytes rather than parsed a second time. The library has verified the
        // structure by this point, and our own AuthenticatorData.Parse ahead of it - on bytes
        // nothing had checked yet - threw a CBOR exception neither catch above covers, which left
        // an anonymous endpoint answering 500 for authenticator data with the extension flag set.
        // Byte 32 is the flags byte and 0x04 is UV, both fixed by the specification.
        var userVerified = (rawAuthenticatorData[32] & (byte)AuthenticatorFlags.UV) != 0;

        // Enrolment alone decides a challenge, exactly as on the password and magic-link paths: a
        // user who turned two-factor on gets asked in every mode. A verified assertion is the two
        // factors already and passes through; one without user verification is possession alone, and
        // letting that mint a token pair would mean a borrowed security key beat the account's own
        // policy.
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

        // hwk is the possession half and user is the presence half, both RFC 8176. mfa is added only
        // when the authenticator actually verified the user - a PIN or a fingerprint - because that
        // is the difference between one factor and two, and it is what the enrolment policy reads.
        List<string> methods = userVerified
            ? [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod, ToamaisutaaDefaults.MultiFactorMethod]
            : [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod];

        var issued = await sessions.IssueAsync(
            new LocalSessionRequest
            {
                User = user,
                Methods = methods,

                // Carried onto the refresh row by the issuer, so a rotation an hour later still
                // reports a passkey session as one - and still satisfies the policies it satisfied
                // at sign-in, rather than turning into a password-only session on the first refresh.
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

    public async Task<bool> DeleteAsync(Guid userId, Guid passkeyId, CancellationToken cancellationToken = default)
    {
        if (!await credentials.DeleteAsync(userId, passkeyId, cancellationToken))
            return false;

        var now = timeProvider.GetUtcNow();

        await events.PublishAsync(
            new PasskeyRemoved { OccurredAt = now, UserId = userId, PasskeyId = passkeyId },
            cancellationToken);

        // Worth a warning rather than an information line: for an account with no password this is
        // the moment the last way in disappeared, and the person doing it may not realise.
        var remaining = await credentials.CountAsync(userId, cancellationToken);

        logger.LogWarning(
            "Deleted passkey {PasskeyId} for user {UserId}. {Remaining} passkey(s) remain on the account.",
            passkeyId,
            userId,
            remaining);

        return true;
    }

    /// <summary>
    /// Refuses to start a registration for a caller who has shown nothing but a bearer token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two proofs are accepted, and they are the two the rest of the package already asks for. A
    /// second factor presented inside <c>Passkeys:RegistrationProofWindow</c> - the same
    /// <c>toa_2fa_at</c> claim <c>RequireFreshSecondFactor</c> reads - covers a passkey sign-in and
    /// a step-up alike. Failing that, the current password, the way <c>/auth/email</c> asks for one.
    /// </para>
    /// <para>
    /// The stores are resolved here rather than injected because an account can perfectly well have
    /// no local password at all: an external identity provider issued its token, or a passkey is the
    /// only credential on it. Those accounts prove a second factor instead, and a constructor
    /// dependency would turn an optional registration into a crash at the first ceremony.
    /// </para>
    /// </remarks>
    private async Task RequireLiveCredentialAsync(
        Guid userId,
        PasskeyRegistrationProof proof,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var window = options.Value.RegistrationProofWindow;

        // A time ahead of now is a clock problem rather than a fresh factor, and refusing keeps a
        // skewed issuer from being a way past this instead of into it.
        if (proof.SecondFactorAt is { } presentedAt && presentedAt <= now && now - presentedAt <= window)
            return;

        var passwords = provider.GetService<IPasswordCredentialStore>();
        var credential = passwords is null ? null : await passwords.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            logger.LogWarning(
                "Passkey registration refused for user {UserId}: the account has no password, and no second factor was presented recently.",
                userId);

            throw new PasskeyRegistrationException(
                "This account has no password to prove, so registering a passkey needs a second factor. Complete a "
                + "step-up, then register while it is still fresh.");
        }

        var hasher = provider.GetService<IPasswordHasher>();

        if (hasher is null || string.IsNullOrEmpty(proof.CurrentPassword)
            || hasher.Verify(proof.CurrentPassword, credential.PasswordHash) == PasswordVerificationResult.Failed)
        {
            logger.LogWarning("Passkey registration refused for user {UserId}: the current password is missing or wrong.", userId);

            throw new PasskeyRegistrationException(
                "Registering a passkey needs proof of a credential this account already has. Send currentPassword, or "
                + "complete a step-up, then register while it is still fresh.");
        }
    }

    /// <summary>
    /// Writes the server's half of a ceremony and hands back the opaque token that names it.
    /// </summary>
    /// <remarks>
    /// The options are stored rather than returned for the client to give back. They carry the
    /// challenge, the relying party and the user verification requirement, and every one of those is
    /// a rule the completion step measures the authenticator against - so a client that could return
    /// them could return different ones and mark its own work.
    /// </remarks>
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
    /// Spends a challenge, if it is the right kind and has not been spent already. Null covers every
    /// way it can fail, because which one it was is not something to confirm to whoever presented it.
    /// </summary>
    /// <remarks>
    /// Consumed before the ceremony is verified rather than after, which is the opposite of the
    /// two-factor challenge next door - and deliberately. A mistyped six-digit code is a routine
    /// human error worth a second try; an authenticator response is produced by software in one
    /// shot, so a failed one is not a typo, and leaving the challenge live would hand an attacker
    /// unlimited attempts against a single one.
    /// </remarks>
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

        await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken);

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
    /// Whether the handle the authenticator chose names the account this credential belongs to.
    /// </summary>
    /// <remarks>
    /// A handle that does not parse as a user id is refused rather than ignored: it is either an
    /// authenticator this application never enrolled, or somebody substituting one credential's
    /// response for another's.
    /// </remarks>
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
    /// What the browser reported, keeping only the values WebAuthn actually defines.
    /// </summary>
    /// <remarks>
    /// An unknown one is dropped rather than refused. The transport list is a hint for the next
    /// sign-in prompt and nothing authorises on it, so a browser inventing a value is not a reason
    /// to refuse a credential that is otherwise perfectly good.
    /// </remarks>
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

    /// <summary>Space-separated, matching how <c>amr</c> is stored on a refresh row. Null when the
    /// browser did not say, which is not the same as an authenticator with no transports.</summary>
    private static string? Describe(AuthenticatorTransport[]? transports) =>
        transports is null or { Length: 0 }
            ? null
            : string.Join(' ', transports.Select(transport => transport.ToString().ToLowerInvariant()));
}
