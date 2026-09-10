using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Registered credentials and the ceremonies in flight against them. One class for the same reason
/// the two-factor stores share one: a single <c>DbContext</c>, registered together, two interfaces.
/// </summary>
internal sealed class EntityFrameworkPasskeyStore<TContext>(TContext context)
    : IPasskeyCredentialStore, IPasskeyChallengeStore
    where TContext : DbContext
{
    // ── Credentials ──

    public async Task<ToamaisutaaPasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .FirstOrDefaultAsync(credential => credential.CredentialId == credentialId, cancellationToken);

    public async Task<IReadOnlyList<ToamaisutaaPasskeyCredential>> ListAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .Where(credential => credential.UserId == userId)
            .OrderByDescending(credential => credential.CreatedAt)
            .ToListAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaPasskeyCredential credential, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasskeyCredential>().Add(credential);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task RecordUseAsync(
        Guid credentialId,
        long signCount,
        bool isBackedUp,
        DateTimeOffset usedAt,
        CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .Where(credential => credential.Id == credentialId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(credential => credential.SignCount, signCount)
                    .SetProperty(credential => credential.IsBackedUp, isBackedUp)
                    .SetProperty(credential => credential.LastUsedAt, usedAt),
                cancellationToken);

    public async Task<bool> DeleteAsync(Guid userId, Guid credentialId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .Where(credential => credential.Id == credentialId && credential.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<int> DeleteAllAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .Where(credential => credential.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task<int> CountAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyCredential>()
            .CountAsync(credential => credential.UserId == userId, cancellationToken);

    // ── Challenges ──

    public async Task CreateAsync(ToamaisutaaPasskeyChallenge challenge, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaPasskeyChallenge>().Add(challenge);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaPasskeyChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyChallenge>()
            .FirstOrDefaultAsync(challenge => challenge.TokenHash == tokenHash, cancellationToken);

    public async Task MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyChallenge>()
            .Where(challenge => challenge.Id == challengeId && challenge.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(challenge => challenge.ConsumedAt, consumedAt), cancellationToken);

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaPasskeyChallenge>()
            .Where(challenge => challenge.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
