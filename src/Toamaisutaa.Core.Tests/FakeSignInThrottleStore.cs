using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

internal sealed class FakeSignInThrottleStore : ISignInThrottleStore
{
    private readonly Dictionary<(Guid, string), ToamaisutaaSignInThrottle> _rows = [];

    public IReadOnlyCollection<ToamaisutaaSignInThrottle> Rows
    {
        get
        {
            lock (_rows)
                return [.. _rows.Values.Select(Copy)];
        }
    }

    public Task<ToamaisutaaSignInThrottle?> FindAsync(Guid userId, string source, CancellationToken cancellationToken = default)
    {
        lock (_rows)
            return Task.FromResult(_rows.TryGetValue((userId, source), out var row) ? Copy(row) : null);
    }

    public Task<bool> UpdateFailedAttemptsAsync(
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
        lock (_rows)
        {
            _rows.TryGetValue((userId, source), out var row);

            var matches = row is null
                ? expectedFailedAttemptCount == 0 && expectedFirstFailedAttemptAt is null && expectedLockedOutUntil is null
                : row.FailedAttemptCount == expectedFailedAttemptCount
                    && row.FirstFailedAttemptAt == expectedFirstFailedAttemptAt
                    && row.LockedOutUntil == expectedLockedOutUntil;

            if (!matches)
                return Task.FromResult(false);

            _rows[(userId, source)] = new ToamaisutaaSignInThrottle
            {
                UserId = userId,
                Source = source,
                FailedAttemptCount = failedAttemptCount,
                FirstFailedAttemptAt = firstFailedAttemptAt,
                LockedOutUntil = lockedOutUntil,
            };

            return Task.FromResult(true);
        }
    }

    public Task DeleteAllForUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        lock (_rows)
        {
            foreach (var key in _rows.Keys.Where(key => key.Item1 == userId).ToList())
                _rows.Remove(key);
        }

        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset now, DateTimeOffset windowStartedBefore, CancellationToken cancellationToken = default)
    {
        lock (_rows)
        {
            var spent = _rows
                .Where(pair => (pair.Value.LockedOutUntil is null || pair.Value.LockedOutUntil <= now)
                    && (pair.Value.FirstFailedAttemptAt is null || pair.Value.FirstFailedAttemptAt < windowStartedBefore))
                .Select(pair => pair.Key)
                .ToList();

            foreach (var key in spent)
                _rows.Remove(key);

            return Task.FromResult(spent.Count);
        }
    }

    private static ToamaisutaaSignInThrottle Copy(ToamaisutaaSignInThrottle row) => new()
    {
        UserId = row.UserId,
        Source = row.Source,
        FailedAttemptCount = row.FailedAttemptCount,
        FirstFailedAttemptAt = row.FirstFailedAttemptAt,
        LockedOutUntil = row.LockedOutUntil,
    };
}
