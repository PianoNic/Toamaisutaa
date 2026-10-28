using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkSignInThrottleStore<TContext>(TContext context) : ISignInThrottleStore
    where TContext : DbContext
{
    // A projection-free read with no tracking, so the conditional writes below are never compared
    // against a row this request read earlier.
    public async Task<ToamaisutaaSignInThrottle?> FindAsync(Guid userId, string source, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaSignInThrottle>()
            .AsNoTracking()
            .FirstOrDefaultAsync(row => row.UserId == userId && row.Source == source, cancellationToken);

    public async Task<bool> UpdateFailedAttemptsAsync(
        Guid userId,
        string source,
        int expectedFailedAttemptCount,
        DateTimeOffset? expectedFirstFailedAttemptAt,
        DateTimeOffset? expectedLockedOutUntil,
        int failedAttemptCount,
        DateTimeOffset? firstFailedAttemptAt,
        DateTimeOffset? lockedOutUntil,
        CancellationToken cancellationToken = default)
    {
        var written = await context.Set<ToamaisutaaSignInThrottle>()
            .Where(row => row.UserId == userId
                && row.Source == source
                && row.FailedAttemptCount == expectedFailedAttemptCount
                && row.FirstFailedAttemptAt == expectedFirstFailedAttemptAt
                && row.LockedOutUntil == expectedLockedOutUntil)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(row => row.FailedAttemptCount, failedAttemptCount)
                    .SetProperty(row => row.FirstFailedAttemptAt, firstFailedAttemptAt)
                    .SetProperty(row => row.LockedOutUntil, lockedOutUntil),
                cancellationToken) == 1;

        if (written)
            return true;

        // Only a clear count can stand for a row that is not there yet.
        if (expectedFailedAttemptCount != 0 || expectedFirstFailedAttemptAt is not null || expectedLockedOutUntil is not null)
            return false;

        var row = new ToamaisutaaSignInThrottle
        {
            UserId = userId,
            Source = source,
            FailedAttemptCount = failedAttemptCount,
            FirstFailedAttemptAt = firstFailedAttemptAt,
            LockedOutUntil = lockedOutUntil,
        };

        context.Set<ToamaisutaaSignInThrottle>().Add(row);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            // Another attempt inserted it first, or the row exists with a count this read missed.
            return false;
        }
        finally
        {
            context.Entry(row).State = EntityState.Detached;
        }
    }

    public async Task DeleteAllForUserAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaSignInThrottle>()
            .Where(row => row.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, DateTimeOffset windowStartedBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaSignInThrottle>()
            .Where(row => (row.LockedOutUntil == null || row.LockedOutUntil <= now)
                && (row.FirstFailedAttemptAt == null || row.FirstFailedAttemptAt < windowStartedBefore))
            .ExecuteDeleteAsync(cancellationToken);
}
