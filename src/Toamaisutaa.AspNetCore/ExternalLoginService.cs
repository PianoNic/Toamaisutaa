using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Sign-in and linking through another identity provider. The provider decides who somebody is; this
/// decides which account that is, and then signs in exactly as a password would.
/// </summary>
internal sealed class ExternalLoginService(
    ExternalProviderClient providers,
    IExternalLoginRequestStore requests,
    IExternalLoginStore logins,
    IUserStore users,
    IClaimsProfileMapper mapper,
    LocalSessionIssuer sessions,
    TwoFactorGate twoFactor,
    AuthenticationEventPublisher events,
    ToamaisutaaMetrics metrics,
    IOptions<ToamaisutaaExternalLoginOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin,
    TimeProvider timeProvider,
    IServiceProvider provider,
    ILogger<ExternalLoginService> logger)
{
    /// <summary>The address to send the browser to at the provider.</summary>
    internal async Task<string> BeginAsync(ExternalLoginStart start, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var settings = options.Value.Providers[start.ProviderKey];
        var configuration = await providers.GetConfigurationAsync(start.ProviderKey, cancellationToken);

        var state = SecureTokens.Create();
        var nonce = SecureTokens.Create();
        var verifier = SecureTokens.Create();

        await requests.CreateAsync(
            new ToamaisutaaExternalLoginRequest
            {
                Id = Guid.CreateVersion7(now),
                ProviderKey = start.ProviderKey,
                StateHash = SecureTokens.HashToken(state),
                Nonce = nonce,
                CodeVerifier = verifier,
                RedirectUri = start.RedirectUri,
                ReturnUrl = start.ReturnUrl,
                ClientState = start.ClientState,
                ClientCodeChallenge = start.ClientCodeChallenge,
                LinkUserId = start.LinkUser?.Id,

                // Compared when the provider answers, so a password change in between refuses the link.
                SecurityStamp = start.LinkUser?.SecurityStamp,

                CreatedAt = now,
                ExpiresAt = now + options.Value.RequestLifetime,
            },
            cancellationToken);

        return QueryHelpers.AddQueryString(configuration.AuthorizationEndpoint, new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = settings.ClientId,
            ["redirect_uri"] = start.RedirectUri,
            ["scope"] = string.Join(' ', settings.Scopes),
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = Challenge(verifier),
            ["code_challenge_method"] = "S256",
        });
    }

    /// <summary>
    /// Where the browser goes once the provider has answered. Null when the answer belongs to no sign-in
    /// begun here, in which case there is nowhere it is safe to send it.
    /// </summary>
    internal async Task<string?> CompleteAsync(
        string providerKey,
        string? code,
        string? state,
        string? error,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();

        if (string.IsNullOrEmpty(state))
            return null;

        var request = await requests.FindByStateHashAsync(SecureTokens.HashToken(state), cancellationToken);

        if (request is null
            || !string.Equals(request.ProviderKey, providerKey, StringComparison.Ordinal)
            || request.ConsumedAt is not null
            || request.ExpiresAt <= now
            || !await requests.MarkStateConsumedAsync(request.Id, now, cancellationToken))
        {
            logger.LogWarning(
                "External sign-in through {ProviderKey} refused: the state is unknown, already answered or expired.",
                providerKey);

            return null;
        }

        if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(code))
        {
            logger.LogInformation(
                "External sign-in through {ProviderKey} ended at the provider: {Error}.",
                providerKey,
                string.IsNullOrEmpty(error) ? "no code was returned" : error);

            // Only the one value a client can act on is passed through; the rest is the provider's vocabulary.
            return Return(request, ("error", error == "access_denied" ? "access_denied" : "external_login_failed"));
        }

        var idToken = await providers.RedeemAsync(providerKey, code, request.CodeVerifier, request.RedirectUri, cancellationToken);
        var identity = idToken is null ? null : await providers.ValidateIdTokenAsync(providerKey, idToken, request.Nonce, cancellationToken);

        if (identity is null)
            return Return(request, ("error", "external_login_failed"));

        var profile = mapper.Map(new ClaimsPrincipal(identity));

        return request.LinkUserId is { } linkUserId
            ? await LinkAsync(request, linkUserId, profile, now, cancellationToken)
            : await SignInAsync(request, profile, now, cancellationToken);
    }

    internal async Task<SignInResult> ExchangeAsync(ExternalLoginExchange exchange, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var request = await requests.FindByExchangeCodeHashAsync(SecureTokens.HashToken(exchange.Code), cancellationToken);

        // Spent before the verifier is compared, so a code read off a redirect gets one guess, not many.
        if (request is not { UserId: { } userId, ClientCodeChallenge: { } expected }
            || request.ExchangeConsumedAt is not null
            || request.ExpiresAt <= now
            || !await requests.MarkExchangeConsumedAsync(request.Id, now, cancellationToken))
        {
            logger.LogWarning("External sign-in exchange refused: the code is unknown, already exchanged or expired.");
            return await RefusedAsync(SignInOutcome.InvalidExternalLogin, request?.UserId, now, cancellationToken);
        }

        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Challenge(exchange.CodeVerifier)), Encoding.ASCII.GetBytes(expected)))
        {
            logger.LogWarning("External sign-in exchange refused for user {UserId}: the verifier does not match the challenge.", userId);
            return await RefusedAsync(SignInOutcome.InvalidExternalLogin, userId, now, cancellationToken);
        }

        var user = await users.FindByIdAsync(userId, cancellationToken);

        if (user is null)
            return await RefusedAsync(SignInOutcome.InvalidExternalLogin, userId, now, cancellationToken);

        if (user.DisabledAt is not null)
        {
            logger.LogWarning("External sign-in refused for user {UserId}: the account is disabled.", user.Id);
            return await RefusedAsync(SignInOutcome.AccountDisabled, user.Id, now, cancellationToken);
        }

        // A credential change since the provider vouched ends this as it ends every session.
        if (!string.Equals(request.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning("External sign-in refused for user {UserId}: a credential changed before the code was exchanged.", user.Id);
            return await RefusedAsync(SignInOutcome.SecurityStampChanged, user.Id, now, cancellationToken);
        }

        // No device token here, as for a magic link: the provider's session plus a cached factor is not two factors.
        if (await twoFactor.RequiresChallengeAsync(user.Id, cancellationToken))
        {
            var challenge = await twoFactor.IssueChallengeAsync(
                user.Id,
                now,
                cancellationToken,
                authenticationMethods: ToamaisutaaDefaults.FederatedMethod,
                securityStamp: user.SecurityStamp);

            logger.LogInformation("External sign-in accepted for user {UserId}; a second factor is required.", user.Id);
            metrics.SignInCompleted(SignInOutcome.TwoFactorRequired, methods: null);

            return new SignInResult { Outcome = SignInOutcome.TwoFactorRequired, Challenge = challenge };
        }

        string[] methods = [ToamaisutaaDefaults.FederatedMethod];

        var issued = await sessions.IssueAsync(
            new LocalSessionRequest
            {
                User = user,
                Methods = methods,
                NewSignIn = true,
                Client = ClientMetadata.Describe(exchange.UserAgent, exchange.IpAddress, localLogin.Value.IpAddressStorage),
                Now = now,
            },
            cancellationToken);

        logger.LogInformation("Sign-in succeeded for user {UserId} through {ProviderKey}.", user.Id, request.ProviderKey);
        metrics.SignInCompleted(SignInOutcome.Succeeded, methods);

        return new SignInResult { Outcome = SignInOutcome.Succeeded, Tokens = issued.Tokens };
    }

    /// <summary>
    /// Linking adds a way into the account, so a bearer token alone is not enough: it takes a code where
    /// there is a second factor, the password where there is one, and otherwise a sign-in moments ago.
    /// </summary>
    /// <returns>Null when proven, otherwise what to tell the caller.</returns>
    internal async Task<string?> ProveAsync(Guid userId, ExternalLoginProof proof, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();

        var enrolled = provider.GetService<ITwoFactorStore>() is { } enrolments
            && await enrolments.FindAsync(userId, cancellationToken) is { ConfirmedAt: not null };

        // A code in this very request: one minutes old on a stolen token would otherwise buy a link that
        // outlives every sign-out.
        if (enrolled)
        {
            if (string.IsNullOrWhiteSpace(proof.Code))
            {
                logger.LogWarning("External login change refused for user {UserId}: the account has a second factor, and no code was sent.", userId);
                return "This account has a second factor, so this needs a code from the authenticator app, or a recovery code, sent as code.";
            }

            if (provider.GetService<ITwoFactorService>() is not TwoFactorService twoFactorService)
                throw new InvalidOperationException("AddToamaisutaaTwoFactor() is not registered, so a code cannot be checked.");

            return await twoFactorService.ProveAsync(userId, proof.Code, cancellationToken);
        }

        var passwords = provider.GetService<IPasswordCredentialStore>();
        var credential = passwords is null ? null : await passwords.FindByUserIdAsync(userId, cancellationToken);

        if (credential is not null)
        {
            var hasher = provider.GetService<IPasswordHasher>();

            if (hasher is null || string.IsNullOrEmpty(proof.CurrentPassword))
            {
                logger.LogWarning("External login change refused for user {UserId}: no current password was given.", userId);
                return "This needs your current password. Send currentPassword.";
            }

            return await passwords!.CheckCurrentPasswordAsync(
                credential,
                proof.CurrentPassword,
                hasher,
                events,
                metrics,
                localLogin.Value,
                logger,
                "External login change",
                now,
                cancellationToken);
        }

        if (await SignedInAtAsync(proof, cancellationToken) is { } at && at <= now && now - at <= options.Value.LinkProofWindow)
            return null;

        logger.LogWarning("External login change refused for user {UserId}: the account has no password, and the session is not fresh.", userId);
        return "This account has no password to prove, so this needs a recent sign-in. Sign in again, then try while that sign-in is fresh.";
    }

    internal Task<IReadOnlyList<ToamaisutaaExternalLogin>> ListAsync(Guid userId, CancellationToken cancellationToken) =>
        logins.ListAsync(userId, cancellationToken);

    internal async Task<UnlinkOutcome> UnlinkAsync(Guid userId, string providerKey, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var linked = await logins.ListAsync(userId, cancellationToken);

        if (!linked.Any(login => string.Equals(login.ProviderKey, providerKey, StringComparison.Ordinal)))
            return UnlinkOutcome.NotLinked;

        if (linked.Count == 1 && !await HasOtherWayInAsync(userId, cancellationToken))
        {
            logger.LogWarning("Unlinking {ProviderKey} refused for user {UserId}: it is the account's only way to sign in.", providerKey, userId);
            return UnlinkOutcome.LastWayIn;
        }

        if (!await logins.DeleteAsync(userId, providerKey, cancellationToken))
            return UnlinkOutcome.NotLinked;

        // Nothing records which session the provider opened, and the usual reason to remove one is that
        // somebody else linked it, so all of them end.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await provider.GetRequiredService<IRefreshTokenStore>().RevokeAllForUserAsync(userId, "external-login-removed", now, cancellationToken);

        await events.PublishAsync(new SessionRevoked { OccurredAt = now, UserId = userId, Reason = "external-login-removed" }, cancellationToken);
        await events.PublishAsync(new ExternalLoginUnlinked { OccurredAt = now, UserId = userId, ProviderKey = providerKey }, cancellationToken);

        logger.LogWarning("Unlinked {ProviderKey} from user {UserId} and ended every session on the account.", providerKey, userId);
        return UnlinkOutcome.Unlinked;
    }

    private async Task<string> SignInAsync(
        ToamaisutaaExternalLoginRequest request,
        ExternalUserProfile profile,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var providerKey = request.ProviderKey;
        var settings = options.Value.Providers[providerKey];
        var user = await FindLinkedAsync(providerKey, profile, cancellationToken);

        if (user is null)
        {
            var holder = await FindByAddressAsync(profile.Email, cancellationToken);

            if (holder is not null)
            {
                if (!settings.LinkByVerifiedEmail || profile.EmailVerified != true)
                {
                    logger.LogInformation(
                        "External sign-in through {ProviderKey} refused: user {UserId} already holds the address, and it was not linked automatically.",
                        providerKey,
                        holder.Id);

                    return Return(request, ("error", "account_exists"));
                }

                if (!await TryLinkAsync(holder.Id, providerKey, profile, cancellationToken))
                    return Return(request, ("error", "external_login_failed"));

                user = holder;

                logger.LogInformation("Linked {ProviderKey} to user {UserId} by its verified address.", providerKey, user.Id);
                await events.PublishAsync(new ExternalLoginLinked { OccurredAt = now, UserId = user.Id, ProviderKey = providerKey }, cancellationToken);
            }
            else if (!settings.AllowSignUp)
            {
                logger.LogInformation("External sign-in through {ProviderKey} refused: no account is linked, and sign-up is off.", providerKey);
                return Return(request, ("error", "account_not_found"));
            }
            else
            {
                user = await CreateAsync(providerKey, profile, now, cancellationToken);

                if (user is null)
                    return Return(request, ("error", "external_login_failed"));
            }
        }

        await events.PublishAsync(new ExternalLoginAuthenticated { OccurredAt = now, UserId = user.Id, ProviderKey = providerKey }, cancellationToken);

        var code = SecureTokens.Create();

        await requests.SetExchangeAsync(
            request.Id,
            SecureTokens.HashToken(code),
            user.Id,
            user.SecurityStamp,
            now + options.Value.ExchangeCodeLifetime,
            cancellationToken);

        return Return(request, ("code", code));
    }

    private async Task<string> LinkAsync(
        ToamaisutaaExternalLoginRequest request,
        Guid userId,
        ExternalUserProfile profile,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var providerKey = request.ProviderKey;
        var user = await users.FindByIdAsync(userId, cancellationToken);

        if (user is null || user.DisabledAt is not null || !string.Equals(user.SecurityStamp, request.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning("Linking {ProviderKey} refused for user {UserId}: the account changed while the provider was asked.", providerKey, userId);
            return Return(request, ("error", "external_login_failed"));
        }

        var existing = await logins.FindAsync(providerKey, profile.Subject, cancellationToken);

        if (existing is not null)
        {
            if (existing.UserId == userId)
                return Return(request, ("linked", providerKey));

            logger.LogWarning(
                "Linking {ProviderKey} refused for user {UserId}: that identity is already linked to user {OtherUserId}.",
                providerKey,
                userId,
                existing.UserId);

            return Return(request, ("error", "linked_to_another_account"));
        }

        // One identity per provider per account, so "unlink Google" always means one thing.
        if ((await logins.ListAsync(userId, cancellationToken)).Any(login => string.Equals(login.ProviderKey, providerKey, StringComparison.Ordinal)))
        {
            logger.LogInformation("Linking {ProviderKey} refused for user {UserId}: another identity there is already linked.", providerKey, userId);
            return Return(request, ("error", "provider_already_linked"));
        }

        if (!await TryLinkAsync(userId, providerKey, profile, cancellationToken))
            return Return(request, ("error", "linked_to_another_account"));

        logger.LogInformation("Linked {ProviderKey} to user {UserId}.", providerKey, userId);
        await events.PublishAsync(new ExternalLoginLinked { OccurredAt = now, UserId = userId, ProviderKey = providerKey }, cancellationToken);

        return Return(request, ("linked", providerKey));
    }

    private async Task<ToamaisutaaUser?> FindLinkedAsync(string providerKey, ExternalUserProfile profile, CancellationToken cancellationToken)
    {
        var login = await logins.FindAsync(providerKey, profile.Subject, cancellationToken);

        if (login is null)
            return null;

        if (ShouldStampSignIn(login))
            await logins.RecordSignInAsync(login.Id, cancellationToken);

        return await users.FindByIdAsync(login.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"External login {login.Id} points at user {login.UserId}, which no longer exists.");
    }

    /// <summary>
    /// Whoever holds the address, on the account or as a password sign-in name. Either way it is
    /// somebody's, and a second account with it would leave two people one inbox.
    /// </summary>
    private async Task<ToamaisutaaUser?> FindByAddressAsync(string? email, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        if (await users.FindByEmailAsync(email, cancellationToken) is { } holder)
            return holder;

        return provider.GetService<IPasswordCredentialStore>() is { } passwords
            && await passwords.FindByNormalizedEmailAsync(Normalizer.Normalize(email), cancellationToken) is { } credential
            ? await users.FindByIdAsync(credential.UserId, cancellationToken)
            : null;
    }

    private async Task<ToamaisutaaUser?> CreateAsync(string providerKey, ExternalUserProfile profile, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var user = await users.CreateAsync(profile, cancellationToken);

        try
        {
            await logins.LinkAsync(user.Id, providerKey, profile, cancellationToken);
        }
        catch (ExternalLoginConflictException)
        {
            // A concurrent first sign-in for the same identity won, and the store discarded this user.
            return await FindLinkedAsync(providerKey, profile, cancellationToken);
        }

        logger.LogInformation("Created user {UserId} on first sign-in through {ProviderKey}.", user.Id, providerKey);
        await events.PublishAsync(new AccountCreated { OccurredAt = now, UserId = user.Id, Source = "external-login" }, cancellationToken);

        return user;
    }

    private async Task<bool> TryLinkAsync(Guid userId, string providerKey, ExternalUserProfile profile, CancellationToken cancellationToken)
    {
        try
        {
            await logins.LinkAsync(userId, providerKey, profile, cancellationToken);
            return true;
        }
        catch (ExternalLoginConflictException)
        {
            return false;
        }
    }

    private async Task<bool> HasOtherWayInAsync(Guid userId, CancellationToken cancellationToken) =>
        (provider.GetService<IPasswordCredentialStore>() is { } passwords && await passwords.FindByUserIdAsync(userId, cancellationToken) is not null)
        || (provider.GetService<IPasskeyCredentialStore>() is { } passkeys && await passkeys.CountAsync(userId, cancellationToken) > 0);

    /// <summary>The later of a live second factor and the start of the calling session.</summary>
    private async Task<DateTimeOffset?> SignedInAtAsync(ExternalLoginProof proof, CancellationToken cancellationToken)
    {
        var started = proof.SessionId is { } family
            && await provider.GetRequiredService<IRefreshTokenStore>().FindLiveByFamilyAsync(family, cancellationToken) is { } live
            ? live.FamilyStartedAt
            : (DateTimeOffset?)null;

        return started is null || proof.AuthenticatedAt > started ? proof.AuthenticatedAt : started;
    }

    private bool ShouldStampSignIn(ToamaisutaaExternalLogin login) =>
        login.LastSignInAt is not { } last || timeProvider.GetUtcNow() - last >= TimeSpan.FromHours(1);

    private async Task<SignInResult> RefusedAsync(SignInOutcome outcome, Guid? userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        metrics.SignInCompleted(outcome, methods: null);
        await events.PublishAsync(new SignInFailed { OccurredAt = now, UserId = userId, Reason = outcome }, cancellationToken);
        return new SignInResult { Outcome = outcome };
    }

    private static string Return(ToamaisutaaExternalLoginRequest request, (string Name, string Value) result)
    {
        var parameters = new Dictionary<string, string?> { [result.Name] = result.Value };

        if (request.ClientState is not null)
            parameters["state"] = request.ClientState;

        return QueryHelpers.AddQueryString(request.ReturnUrl, parameters);
    }

    /// <summary>RFC 7636 S256.</summary>
    internal static string Challenge(string verifier) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
}

internal sealed record ExternalLoginStart
{
    internal required string ProviderKey { get; init; }

    internal required string RedirectUri { get; init; }

    internal required string ReturnUrl { get; init; }

    internal string? ClientState { get; init; }

    internal string? ClientCodeChallenge { get; init; }

    internal ToamaisutaaUser? LinkUser { get; init; }
}

internal sealed record ExternalLoginExchange(string Code, string CodeVerifier, string? UserAgent, string? IpAddress);

/// <summary>What the caller presented, with the session's freshness read off its own token.</summary>
internal sealed record ExternalLoginProof
{
    internal string? CurrentPassword { get; init; }

    internal string? Code { get; init; }

    internal DateTimeOffset? AuthenticatedAt { get; init; }

    internal Guid? SessionId { get; init; }
}

internal enum UnlinkOutcome
{
    Unlinked,
    NotLinked,
    LastWayIn,
}
