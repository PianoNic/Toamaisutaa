using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkEmailVerificationStore<TContext>(TContext context)
    : IEmailVerificationChallengeStore,
        IEmailVerificationCodeStore
    where TContext : DbContext
{
    public async Task CreateAsync(ToamaisutaaEmailVerificationChallenge challenge, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaEmailVerificationChallenge>().Add(challenge);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaEmailVerificationChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaEmailVerificationChallenge>()
            .AsNoTracking()
            .FirstOrDefaultAsync(challenge => challenge.TokenHash == tokenHash, cancellationToken);

    async Task<bool> IEmailVerificationChallengeStore.MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationChallenge>()
            .Where(challenge => challenge.Id == challengeId && challenge.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(challenge => challenge.ConsumedAt, consumedAt), cancellationToken) == 1;

    async Task<int> IEmailVerificationChallengeStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationChallenge>()
            .Where(challenge => challenge.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaEmailVerificationCode code, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaEmailVerificationCode>().Add(code);
        await context.SaveChangesAsync(cancellationToken);
    }

    // Untracked, so the attempt count is the one the conditional writes left, not an identity-map copy.
    public async Task<ToamaisutaaEmailVerificationCode?> FindLatestAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaEmailVerificationCode>()
            .AsNoTracking()
            .Where(code => code.UserId == userId)

            // Outstanding first: a new code and the one it retired can share a millisecond.
            .OrderBy(code => code.ConsumedAt != null)
            .ThenByDescending(code => code.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

    public async Task<bool> TryReserveAttemptAsync(Guid codeId, int maxAttempts, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaEmailVerificationCode>()
            .Where(code => code.Id == codeId && code.ConsumedAt == null && code.FailedAttempts < maxAttempts)
            .ExecuteUpdateAsync(setters => setters.SetProperty(code => code.FailedAttempts, code => code.FailedAttempts + 1), cancellationToken) == 1;

    async Task<bool> IEmailVerificationCodeStore.MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationCode>()
            .Where(code => code.Id == codeId && code.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(code => code.ConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaEmailVerificationCode>()
            .Where(code => code.UserId == userId && code.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(code => code.ConsumedAt, consumedAt), cancellationToken);

    async Task<int> IEmailVerificationCodeStore.DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaEmailVerificationCode>()
            .Where(code => code.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
