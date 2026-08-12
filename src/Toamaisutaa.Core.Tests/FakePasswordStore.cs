using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>In-memory credential, refresh-token and reset-token storage, including the unique
/// identifier constraint the real store gets from its indexes.</summary>
internal sealed class FakePasswordStore
    : IPasswordCredentialStore, IRefreshTokenStore, IPasswordResetTokenStore
{
    internal List<ToamaisutaaPasswordCredential> Credentials { get; } = [];

    internal List<ToamaisutaaRefreshToken> RefreshTokens { get; } = [];

    internal List<ToamaisutaaPasswordResetToken> ResetTokens { get; } = [];

    // ── Credentials ──

    public Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.FirstOrDefault(credential => credential.UserId == userId));

    public Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.FirstOrDefault(
            credential => credential.NormalizedUserName == normalizedIdentifier || credential.NormalizedEmail == normalizedIdentifier));

    public Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.FirstOrDefault(credential => credential.NormalizedEmail == normalizedEmail));

    public Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default)
    {
        var taken = Credentials.Any(other =>
            other.UserId != credential.UserId
            && (other.NormalizedUserName == credential.NormalizedUserName
                || (credential.NormalizedEmail is not null && other.NormalizedEmail == credential.NormalizedEmail)));

        if (taken)
            throw new PasswordIdentifierConflictException();

        Credentials.Add(credential);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    // ── Refresh tokens ──

    public Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        Task.FromResult(RefreshTokens.FirstOrDefault(token => token.TokenHash == tokenHash));

    public Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default)
    {
        RefreshTokens.Add(token);
        return Task.CompletedTask;
    }

    public Task MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default)
    {
        var token = RefreshTokens.First(entry => entry.Id == tokenId);
        token.RotatedAt = rotatedAt;
        return Task.CompletedTask;
    }

    public Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Live(familyId));

    public Task<bool> UpdateSecondFactorAsync(
        Guid familyId,
        string authenticationMethods,
        string twoFactorSource,
        DateTimeOffset secondFactorAt,
        CancellationToken cancellationToken = default)
    {
        var live = Live(familyId);

        if (live is null)
            return Task.FromResult(false);

        live.AuthenticationMethods = authenticationMethods;
        live.TwoFactorSource = twoFactorSource;
        live.SecondFactorAt = secondFactorAt;

        return Task.FromResult(true);
    }

    private ToamaisutaaRefreshToken? Live(Guid familyId) =>
        RefreshTokens.SingleOrDefault(
            entry => entry.FamilyId == familyId && entry.RotatedAt is null && entry.RevokedAt is null);

    public Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        foreach (var token in RefreshTokens.Where(entry => entry.FamilyId == familyId && entry.RevokedAt is null))
        {
            token.RevokedAt = revokedAt;
            token.RevokedReason = reason;
        }

        return Task.CompletedTask;
    }

    public Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        foreach (var token in RefreshTokens.Where(entry => entry.UserId == userId && entry.RevokedAt is null))
        {
            token.RevokedAt = revokedAt;
            token.RevokedReason = reason;
        }

        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        Task.FromResult(RefreshTokens.RemoveAll(token => token.ExpiresAt <= expiredBefore));

    // ── Reset tokens ──

    public Task CreateAsync(ToamaisutaaPasswordResetToken token, CancellationToken cancellationToken = default)
    {
        ResetTokens.Add(token);
        return Task.CompletedTask;
    }

    Task<ToamaisutaaPasswordResetToken?> IPasswordResetTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        Task.FromResult(ResetTokens.FirstOrDefault(token => token.TokenHash == tokenHash));

    public Task MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var token = ResetTokens.First(entry => entry.Id == tokenId);
        token.ConsumedAt ??= consumedAt;
        return Task.CompletedTask;
    }

    public Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        foreach (var token in ResetTokens.Where(entry => entry.UserId == userId && entry.ConsumedAt is null))
            token.ConsumedAt = consumedAt;

        return Task.CompletedTask;
    }

    Task<int> IPasswordResetTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        Task.FromResult(ResetTokens.RemoveAll(token => token.ExpiresAt <= expiredBefore));
}

internal sealed class FakeAccessTokenIssuer(TimeProvider timeProvider) : IAccessTokenIssuer
{
    internal List<AccessTokenRequest> Issued { get; } = [];

    public Task<AccessToken> IssueAsync(AccessTokenRequest request, CancellationToken cancellationToken = default)
    {
        Issued.Add(request);
        return Task.FromResult(new AccessToken($"access-token-for-{request.User.Id}", timeProvider.GetUtcNow().AddMinutes(15)));
    }
}

internal sealed class FakePasswordResetNotifier : IPasswordResetNotifier
{
    internal List<(Guid UserId, string Token)> Sent { get; } = [];

    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        Sent.Add((user.Id, resetToken));
        return Task.CompletedTask;
    }
}
