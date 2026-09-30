using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkTwoFactorStore<TContext>(TContext context)
    : ITwoFactorStore, IRecoveryCodeStore, ITwoFactorChallengeStore
    where TContext : DbContext
{
    public async Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUserTwoFactor>()
            .FirstOrDefaultAsync(enrolment => enrolment.UserId == userId, cancellationToken);

    public async Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrolment);

        var set = context.Set<ToamaisutaaUserTwoFactor>();

        // The context may already track this entity (BeginEnrolmentAsync reads it first), so check
        // the tracker before the database.
        var tracked = context.Entry(enrolment).State != EntityState.Detached
            || await set.AnyAsync(existing => existing.UserId == enrolment.UserId, cancellationToken);

        if (tracked)
            set.Update(enrolment);
        else
            set.Add(enrolment);

        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> ReplacePendingAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrolment);

        var set = context.Set<ToamaisutaaUserTwoFactor>();

        // Detached so a later SaveChanges cannot write this copy back over whatever the conditional
        // write below decided.
        var tracked = context.ChangeTracker.Entries<ToamaisutaaUserTwoFactor>()
            .FirstOrDefault(entry => entry.Entity.UserId == enrolment.UserId);

        if (tracked is not null)
            tracked.State = EntityState.Detached;

        var replaced = await set
            .Where(existing => existing.UserId == enrolment.UserId && existing.ConfirmedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(existing => existing.SecretCiphertext, enrolment.SecretCiphertext)
                    .SetProperty(existing => existing.SecretNonce, enrolment.SecretNonce)
                    .SetProperty(existing => existing.SecretTag, enrolment.SecretTag)
                    .SetProperty(existing => existing.EncryptionKeyVersion, enrolment.EncryptionKeyVersion)
                    .SetProperty(existing => existing.LastUsedStep, (long?)null)
                    .SetProperty(existing => existing.UpdatedAt, enrolment.UpdatedAt),
                cancellationToken);

        if (replaced == 1)
            return true;

        // Nothing replaced: either there is a confirmed row, which stays, or there is no row yet.
        if (await set.AnyAsync(existing => existing.UserId == enrolment.UserId, cancellationToken))
            return false;

        set.Add(enrolment);
        await context.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        // Detach first, or the next SaveChanges on this request writes the deleted row back.
        var tracked = context.ChangeTracker.Entries<ToamaisutaaUserTwoFactor>()
            .FirstOrDefault(entry => entry.Entity.UserId == userId);

        if (tracked is not null)
            tracked.State = EntityState.Detached;

        await context.Set<ToamaisutaaUserTwoFactor>()
            .Where(enrolment => enrolment.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUserTwoFactor>()
            .Where(enrolment => enrolment.UserId == userId && (enrolment.LastUsedStep == null || enrolment.LastUsedStep < step))
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(enrolment => enrolment.LastUsedStep, step),
                cancellationToken) == 1;

    public async Task<bool> UpdateFailedAttemptsAsync(
        Guid userId,
        int expectedFailedAttemptCount,
        DateTimeOffset? expectedFirstFailedAttemptAt,
        DateTimeOffset? expectedLockedOutUntil,
        int failedAttemptCount,
        DateTimeOffset? firstFailedAttemptAt,
        DateTimeOffset? lockedOutUntil,
        CancellationToken cancellationToken = default)
    {
        var written = await context.Set<ToamaisutaaUserTwoFactor>()
            .Where(enrolment => enrolment.UserId == userId
                && enrolment.FailedAttemptCount == expectedFailedAttemptCount
                && enrolment.FirstFailedAttemptAt == expectedFirstFailedAttemptAt
                && enrolment.LockedOutUntil == expectedLockedOutUntil)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(enrolment => enrolment.FailedAttemptCount, failedAttemptCount)
                    .SetProperty(enrolment => enrolment.FirstFailedAttemptAt, firstFailedAttemptAt)
                    .SetProperty(enrolment => enrolment.LockedOutUntil, lockedOutUntil),
                cancellationToken) == 1;

        // The write bypassed the change tracker; reload so a later whole-row write cannot put an old
        // count back.
        var tracked = context.ChangeTracker.Entries<ToamaisutaaUserTwoFactor>()
            .FirstOrDefault(entry => entry.Entity.UserId == userId);

        if (tracked is not null)
            await tracked.ReloadAsync(cancellationToken);

        return written;
    }

    public async Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(codes);

        // Deleted rather than marked consumed, or CountUnusedAsync would count superseded codes.
        await context.Set<ToamaisutaaRecoveryCode>()
            .Where(code => code.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        if (codes.Count == 0)
            return;

        context.Set<ToamaisutaaRecoveryCode>().AddRange(codes);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .FirstOrDefaultAsync(
                code => code.UserId == userId && code.CodeHash == codeHash && code.ConsumedAt == null,
                cancellationToken);

    public async Task<bool> MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .Where(code => code.Id == codeId && code.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(code => code.ConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .CountAsync(code => code.UserId == userId && code.ConsumedAt == null, cancellationToken);

    public async Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaTwoFactorChallenge>().Add(challenge);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .FirstOrDefaultAsync(challenge => challenge.TokenHash == tokenHash, cancellationToken);

    async Task<bool> ITwoFactorChallengeStore.MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .Where(challenge => challenge.Id == challengeId && challenge.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(challenge => challenge.ConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .Where(challenge => challenge.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
