using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Credentials, refresh tokens, and the reset, invitation, email verification and magic-link tokens.
/// One class because they share a <c>DbContext</c> and are always registered together; each
/// interface is still separate, so an application can replace one of them without the others.
/// </summary>
internal sealed class EntityFrameworkPasswordStore<TContext>(TContext context)
    : IPasswordCredentialStore,
        IRefreshTokenStore,
        IPasswordResetTokenStore,
        IInvitationTokenStore,
        IEmailVerificationTokenStore,
        IMagicLinkTokenStore
    where TContext : DbContext
{
    // ── Credentials ──

    // Every credential read is tracked explicitly, whatever the context's default. UpdateAsync writes
    // what changed since the read and compares the concurrency tokens against it, and neither can
    // happen for an instance the context never tracked: under a no-tracking default a password change
    // or a lockout returned success and wrote nothing.

    public async Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
            .FirstOrDefaultAsync(credential => credential.UserId == userId, cancellationToken);

    public async Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default)
    {
        var matches = await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
            .Where(credential => credential.NormalizedUserName == normalizedIdentifier
                || credential.NormalizedEmail == normalizedIdentifier)
            .Take(2)
            .ToListAsync(cancellationToken);

        if (matches.Count < 2)
            return matches.SingleOrDefault();

        // One account's user name is another's address - written before creation checked across both
        // columns, or by a race with it. Each unique index still holds, so one row matched each column.
        // Chosen by what the identifier looks like rather than whichever row the database returns
        // first, so a user name squatting somebody's address cannot take their email sign-ins.
        return normalizedIdentifier.Contains('@')
            ? matches.Single(credential => credential.NormalizedEmail == normalizedIdentifier)
            : matches.Single(credential => credential.NormalizedUserName == normalizedIdentifier);
    }

    public async Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasswordCredential>()
            .AsTracking()
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
        var entry = context.Entry(credential);

        // Tracked is the normal case - the flows update the row they just read, and the reads above
        // always track - and it is what makes this safe: only changed columns are written, and the
        // concurrency tokens are compared against the values that were read. Update() would mark every
        // column modified and write the whole stale row back.
        //
        // An instance this context never saw carries no record of what it was read as, so there is
        // nothing to compare against: it is written over the current row, last write wins. Only a
        // caller that built or cached a credential itself ends up here.
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
            // So the caller's next read sees the row as it is now rather than this context's copy.
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

    // ── Refresh tokens ──

    // Untracked, because every write to a refresh token is an ExecuteUpdate that never touches a
    // tracked instance: tracked, a second read in the same request handed back the first one's
    // values, and rotation re-reads to tell a revocation from a reuse.
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

    /// <summary>
    /// The live row of each family: not rotated, not revoked. Rotated rows stay in the table because
    /// reuse detection needs them, but they are not sessions anybody has.
    /// </summary>
    public async Task<IReadOnlyList<ToamaisutaaRefreshToken>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRefreshToken>()
            .Where(token => token.UserId == userId && token.RotatedAt == null && token.RevokedAt == null)
            .ToListAsync(cancellationToken);

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

    // ── Invitation tokens ──

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

    async Task<ToamaisutaaInvitationToken?> IInvitationTokenStore.FindOpenByEmailAsync(
        string normalizedEmail,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.NormalizedEmail == normalizedEmail && token.ConsumedAt == null && token.ExpiresAt > now)
            .OrderByDescending(token => token.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

    async Task IInvitationTokenStore.InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaInvitationToken>()
            .Where(token => token.UserId == userId && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.ConsumedAt, consumedAt), cancellationToken);

    // ── Email verification tokens ──

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

    // ── Magic-link tokens ──

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
