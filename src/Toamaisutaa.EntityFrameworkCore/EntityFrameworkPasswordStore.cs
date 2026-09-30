using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkPasswordStore<TContext>(TContext context)
    : IPasswordCredentialStore,
        IRefreshTokenStore,
        IPasswordResetTokenStore,
        IInvitationTokenStore,
        IEmailVerificationTokenStore,
        IMagicLinkTokenStore
    where TContext : DbContext
{
    // Credential reads always track, because UpdateAsync relies on change tracking to write changes
    // and compare concurrency tokens; under a no-tracking default it would silently write nothing.

    public async Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
            .FirstOrDefaultAsync(credential => credential.UserId == userId, cancellationToken);

    public async Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default)
    {
        // Filtered ordinally after the query: MySQL's collation would also hand back rows that match
        // only by ignoring accents, and a sign-in has no business resolving an alias.
        var matches = (await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
            .Where(credential => credential.NormalizedUserName == normalizedIdentifier
                || credential.NormalizedEmail == normalizedIdentifier)
            .ToListAsync(cancellationToken))
            .Where(credential => string.Equals(credential.NormalizedUserName, normalizedIdentifier, StringComparison.Ordinal)
                || string.Equals(credential.NormalizedEmail, normalizedIdentifier, StringComparison.Ordinal))
            .Take(2)
            .ToList();

        if (matches.Count < 2)
            return matches.SingleOrDefault();

        // One account's user name is another's address. Chosen by the identifier's shape rather than
        // row order, so a user name squatting somebody's address cannot take their email sign-ins.
        return normalizedIdentifier.Contains('@')
            ? matches.Single(credential => credential.NormalizedEmail == normalizedIdentifier)
            : matches.Single(credential => credential.NormalizedUserName == normalizedIdentifier);
    }

    // Re-compared ordinally because MySQL's default collation ignores accents, so VÍCTIM@ would match
    // VICTIM@'s row and slip past a cooldown that tells them apart.
    public async Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
            .FirstOrDefaultAsync(credential => credential.NormalizedEmail == normalizedEmail, cancellationToken) is { } found
            && string.Equals(found.NormalizedEmail, normalizedEmail, StringComparison.Ordinal)
                ? found
                : null;

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
            // code.
            if (!await IdentifierTakenAsync(credential, cancellationToken))
                throw;

            throw new PasswordIdentifierConflictException(exception);
        }
    }

    public async Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default)
    {
        var entry = context.Entry(credential);

        // Not Update(), which would mark every column modified and write a stale row back over the
        // concurrency check. An untracked instance has nothing to compare against, so it is last write wins.
        if (entry.State == EntityState.Detached)
        {
            var tracked = await context.Set<ToamaisutaaPasswordCredential>()
                .AsTracking()
                .FirstOrDefaultAsync(stored => stored.UserId == credential.UserId, cancellationToken)
                ?? throw new InvalidOperationException($"There is no credential for user {credential.UserId} to update.");

            entry = context.Entry(tracked);
            entry.CurrentValues.SetValues(credential);
        }

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            await entry.ReloadAsync(cancellationToken);
            throw new CredentialConcurrencyException(exception);
        }
    }

    private async Task<bool> IdentifierTakenAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsNoTracking()
            .AnyAsync(
                other => other.UserId != credential.UserId
                    && (other.NormalizedUserName == credential.NormalizedUserName
                        || (credential.NormalizedEmail != null && other.NormalizedEmail == credential.NormalizedEmail)),
                cancellationToken);

    // Untracked, because writes are ExecuteUpdate and rotation re-reads to tell a revocation from a
    // reuse; a tracked read would hand back the first read's stale values.
    public async Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .AsNoTracking()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    public async Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaRefreshToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.Id == tokenId && token.RotatedAt == null && token.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RotatedAt, rotatedAt), cancellationToken) == 1;

    public Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        RevokeUntilNoneLeftAsync(token => token.FamilyId == familyId && token.RevokedAt == null, reason, revokedAt, cancellationToken);

    public Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        RevokeUntilNoneLeftAsync(token => token.UserId == userId && token.RevokedAt == null, reason, revokedAt, cancellationToken);

    // Repeated until it matches nothing. On PostgreSQL, and SQL Server under snapshot reads, one
    // UPDATE never sees a row inserted after it started, and a rotation checking its parent right
    // then does not see this revocation either - so the new token stayed live. The next statement
    // starts after this one committed, and catches it.
    private async Task RevokeUntilNoneLeftAsync(
        System.Linq.Expressions.Expression<Func<ToamaisutaaRefreshToken, bool>> live,
        string reason,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        for (var pass = 0; pass < 10; pass++)
        {
            var revoked = await context.Set<ToamaisutaaRefreshToken>()
                .Where(live)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(token => token.RevokedAt, revokedAt)
                        .SetProperty(token => token.RevokedReason, reason),
                    cancellationToken);

            if (revoked == 0)
                return;
        }
    }

    public async Task<IReadOnlyList<ToamaisutaaRefreshToken>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.UserId == userId && token.RotatedAt == null && token.RevokedAt == null)
            .ToListAsync(cancellationToken);

    public async Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .FirstOrDefaultAsync(
                token => token.FamilyId == familyId && token.RotatedAt == null && token.RevokedAt == null,
                cancellationToken);

    /// <summary>Scoped to the family's live row, so a client that refreshed before stepping up still
    /// has the current row updated.</summary>
    public async Task<bool> UpdateSecondFactorAsync(
        Guid familyId,
        string authenticationMethods,
        string twoFactorSource,
        DateTimeOffset secondFactorAt,
        CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.FamilyId == familyId && token.RotatedAt == null && token.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(token => token.AuthenticationMethods, authenticationMethods)
                    .SetProperty(token => token.TwoFactorSource, twoFactorSource)
                    .SetProperty(token => token.SecondFactorAt, secondFactorAt),
                cancellationToken) > 0;

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaPasswordResetToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasswordResetToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    async Task<ToamaisutaaPasswordResetToken?> IPasswordResetTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    public async Task<bool> MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.Id == tokenId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    async Task<int> IPasswordResetTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaPasswordResetToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaInvitationToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaInvitationToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    async Task<ToamaisutaaInvitationToken?> IInvitationTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    async Task<bool> IInvitationTokenStore.MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.Id == tokenId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken) == 1;

    async Task<int> IInvitationTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    // Re-compared ordinally for the reason FindByNormalizedEmailAsync gives: on MySQL an accented
    // address found, reused and revoked the invitation of the plain one.
    async Task<ToamaisutaaInvitationToken?> IInvitationTokenStore.FindOpenByEmailAsync(
        string normalizedEmail,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        (await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.NormalizedEmail == normalizedEmail && token.ConsumedAt == null && token.ExpiresAt > now)
            .OrderByDescending(token => token.CreatedAt)
            .ToListAsync(cancellationToken))
        .FirstOrDefault(token => string.Equals(token.NormalizedEmail, normalizedEmail, StringComparison.Ordinal));

    async Task IInvitationTokenStore.InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    public async Task CreateAsync(ToamaisutaaEmailVerificationToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaEmailVerificationToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    async Task<ToamaisutaaEmailVerificationToken?> IEmailVerificationTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    async Task<bool> IEmailVerificationTokenStore.MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationToken>()
            .Where(token => token.Id == tokenId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken) == 1;

    async Task IEmailVerificationTokenStore.InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    async Task<int> IEmailVerificationTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaMagicLinkToken token, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaMagicLinkToken>().Add(token);
        await context.SaveChangesAsync(cancellationToken);
    }

    async Task<ToamaisutaaMagicLinkToken?> IMagicLinkTokenStore.FindByHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaMagicLinkToken>()
            .FirstOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

    async Task<bool> IMagicLinkTokenStore.MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaMagicLinkToken>()
            .Where(token => token.Id == tokenId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken) == 1;

    async Task IMagicLinkTokenStore.InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaMagicLinkToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    async Task<int> IMagicLinkTokenStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaMagicLinkToken>()
            .Where(token => token.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
