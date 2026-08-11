using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class PasswordSignInService(
    IPasswordCredentialStore credentials,
    IUserStore users,
    IRefreshTokenStore refreshTokens,
    IPasswordHasher hasher,
    IAccessTokenIssuer accessTokens,
    IUserRoleProvider roles,
    DummyPasswordHash dummy,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<PasswordSignInService> logger) : IPasswordSignInService
{
    public async Task<SignInResult> SignInAsync(string identifier, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(password);

        var now = timeProvider.GetUtcNow();
        var credential = await credentials.FindByIdentifierAsync(Normalizer.Normalize(identifier), cancellationToken);

        if (credential is null)
        {
            // Pay the same price a real account would, so the clock does not answer what the body
            // will not.
            dummy.Verify(password);
            logger.LogInformation("Sign-in refused: no local credential matches the identifier presented.");
            return Failed(SignInOutcome.UnknownUser);
        }

        if (LockoutPolicy.IsLockedOut(credential, now))
        {
            dummy.Verify(password);
            logger.LogWarning(
                "Sign-in refused for user {UserId}: locked out until {LockedOutUntil}.",
                credential.UserId,
                credential.LockedOutUntil);
            return Failed(SignInOutcome.LockedOut);
        }

        var verification = hasher.Verify(password, credential.PasswordHash);

        if (verification == PasswordVerificationResult.Failed)
        {
            LockoutPolicy.RegisterFailure(credential, options.Value, now);
            credential.UpdatedAt = now;
            await credentials.UpdateAsync(credential, cancellationToken);

            logger.LogWarning(
                "Sign-in refused for user {UserId}: wrong password. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
                credential.UserId,
                credential.FailedAttemptCount,
                credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);

            return Failed(SignInOutcome.InvalidPassword);
        }

        if (verification == PasswordVerificationResult.SucceededRehashNeeded)
        {
            // The only moment the plaintext exists. Take it.
            credential.PasswordHash = hasher.Hash(password);
            logger.LogInformation("Rehashed the stored password for user {UserId} with current parameters.", credential.UserId);
        }

        LockoutPolicy.RegisterSuccess(credential);
        credential.UpdatedAt = now;
        await credentials.UpdateAsync(credential, cancellationToken);

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Credential for user {credential.UserId} has no user row.");

        logger.LogInformation("Sign-in succeeded for user {UserId}.", user.Id);
        return await IssueAsync(user, familyId: null, familyStartedAt: null, now, cancellationToken);
    }

    public async Task<SignInResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var now = timeProvider.GetUtcNow();
        var stored = await refreshTokens.FindByHashAsync(SecureTokens.HashToken(refreshToken), cancellationToken);

        if (stored is null)
            return Failed(SignInOutcome.InvalidRefreshToken);

        if (stored.RotatedAt is not null)
        {
            // This token was already exchanged, so two parties hold the chain and one of them is
            // not the account owner. There is no way to tell which, so neither keeps it.
            logger.LogWarning(
                "Refresh token reuse detected for user {UserId}. Token {TokenId} was already rotated at {RotatedAt}; "
                + "revoking the whole family {FamilyId}. Treat this as a possible stolen token.",
                stored.UserId,
                stored.Id,
                stored.RotatedAt,
                stored.FamilyId);

            await refreshTokens.RevokeFamilyAsync(stored.FamilyId, "refresh-token-reuse", now, cancellationToken);
            return Failed(SignInOutcome.RefreshTokenReused);
        }

        if (stored.RevokedAt is not null)
            return Failed(SignInOutcome.RefreshTokenRevoked);

        if (stored.ExpiresAt <= now)
            return Failed(SignInOutcome.RefreshTokenExpired);

        // Rotation keeps a session alive indefinitely on its own. The family's own age is what
        // eventually sends someone back to the login form.
        if (now - stored.FamilyStartedAt >= options.Value.RefreshTokenAbsoluteLifetime)
        {
            logger.LogInformation(
                "Refresh refused for user {UserId}: family {FamilyId} reached its absolute lifetime.",
                stored.UserId,
                stored.FamilyId);

            await refreshTokens.RevokeFamilyAsync(stored.FamilyId, "absolute-lifetime-reached", now, cancellationToken);
            return Failed(SignInOutcome.RefreshTokenExpired);
        }

        await refreshTokens.MarkRotatedAsync(stored.Id, now, cancellationToken);

        var user = await users.FindByIdAsync(stored.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Refresh token {stored.Id} points at user {stored.UserId}, which does not exist.");

        return await IssueAsync(user, stored.FamilyId, stored.FamilyStartedAt, now, cancellationToken);
    }

    public async Task SignOutAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var stored = await refreshTokens.FindByHashAsync(SecureTokens.HashToken(refreshToken), cancellationToken);
        if (stored is null)
            return;

        // The whole family, not just this token: signing out on one device should not leave a
        // rotated sibling alive somewhere else.
        await refreshTokens.RevokeFamilyAsync(stored.FamilyId, "signed-out", timeProvider.GetUtcNow(), cancellationToken);
        logger.LogInformation("Signed out user {UserId}; revoked refresh family {FamilyId}.", stored.UserId, stored.FamilyId);
    }

    private async Task<SignInResult> IssueAsync(
        ToamaisutaaUser user,
        Guid? familyId,
        DateTimeOffset? familyStartedAt,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var userRoles = await roles.GetRolesAsync(user, cancellationToken);
        var access = accessTokens.Issue(user, userRoles);

        var raw = SecureTokens.Create();

        await refreshTokens.CreateAsync(
            new ToamaisutaaRefreshToken
            {
                Id = Guid.CreateVersion7(now),
                UserId = user.Id,
                FamilyId = familyId ?? Guid.CreateVersion7(now),
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.RefreshTokenLifetime,
                FamilyStartedAt = familyStartedAt ?? now,
            },
            cancellationToken);

        return new SignInResult
        {
            Outcome = SignInOutcome.Succeeded,
            Tokens = new TokenPair
            {
                AccessToken = access.Value,
                RefreshToken = raw,
                ExpiresIn = (int)Math.Max(0, (access.ExpiresAt - now).TotalSeconds),
            },
        };
    }

    private static SignInResult Failed(SignInOutcome outcome) => new() { Outcome = outcome };
}
