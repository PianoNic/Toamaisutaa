using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Credentials, refresh tokens and reset tokens. One class because they share a
/// <c>DbContext</c> and are always registered together; each interface is still separate, so an
/// application can replace one of them without the others.
/// </summary>
internal sealed class EntityFrameworkPasswordStore<TContext>(TContext context)
    : IPasswordCredentialStore, IRefreshTokenStore, IPasswordResetTokenStore
    where TContext : DbContext
{
    // ── Credentials ──

    public async Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .FirstOrDefaultAsync(credential => credential.UserId == userId, cancellationToken);

    public async Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .FirstOrDefaultAsync(
                credential => credential.NormalizedUserName == normalizedIdentifier
                    || credential.NormalizedEmail == normalizedIdentifier,
                cancellationToken);

    public async Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .FirstOrDefaultAsync(credential => credential.NormalizedEmail == normalizedEmail, cancellationToken);

    public async Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasswordCredential>().Add(credential);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception)
        {
            context.Entry(credential).State = EntityState.Detached;

            // Which index fired is provider-specific, so ask the database rather than parse an error
            // code: if either identifier is taken now and we did not put it there, that is the
            // conflict.
            if (!await IdentifierTakenAsync(credential, cancellationToken))
                throw;

            throw new PasswordIdentifierConflictException(exception);
        }
    }

    public async Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasswordCredential>().Update(credential);
        await context.SaveChangesAsync(cancellationToken);
    }

    private async Task<bool> IdentifierTakenAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsNoTracking()
            .AnyAsync(
                other => other.UserId != credential.UserId
                    && (other.NormalizedUserName == credential.NormalizedUserName
                        || (credential.NormalizedEmail != null && other.NormalizedEmail == credential.NormalizedEmail)),
                cancellationToken);

    // ── Refresh tokens ──

    public async Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    public async Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaRefreshToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.Id == tokenId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RotatedAt, rotatedAt), cancellationToken);

    public async Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.FamilyId == familyId && token.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(token => token.RevokedAt, revokedAt)
                    .SetProperty(token => token.RevokedReason, reason),
                cancellationToken);

    public async Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.UserId == userId && token.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(token => token.RevokedAt, revokedAt)
                    .SetProperty(token => token.RevokedReason, reason),
                cancellationToken);

    public async Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .FirstOrDefaultAsync(
                token => token.FamilyId == familyId && token.RotatedAt == null && token.RevokedAt == null,
                cancellationToken);

    /// <summary>
    /// The only place this package writes over a refresh row instead of rotating it. Scoped to the
    /// family's live row, so a client that refreshed between receiving its token and stepping up
    /// still has the row that matters updated rather than the one it was minted alongside.
    /// </summary>
    public async Task<bool> UpdateSecondFactorAsync(
        Guid familyId,
        string authenticationMethods,
        string twoFactorSource,
        DateTimeOffset secondFactorAt,
        CancellationToken cancellationToken = default)
    {
        var updated = await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.FamilyId == familyId && token.RotatedAt == null && token.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(token => token.AuthenticationMethods, authenticationMethods)
                    .SetProperty(token => token.TwoFactorSource, twoFactorSource)
                    .SetProperty(token => token.SecondFactorAt, secondFactorAt),
                cancellationToken);

        return updated > 0;
    }

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    // ── Reset tokens ──

    public async Task CreateAsync(ToamaisutaaPasswordResetToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasswordResetToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    async Task<ToamaisutaaPasswordResetToken?> IPasswordResetTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    public async Task MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.Id == tokenId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    public async Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    async Task<int> IPasswordResetTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
