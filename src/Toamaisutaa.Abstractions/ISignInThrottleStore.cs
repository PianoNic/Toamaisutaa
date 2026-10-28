namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for <see cref="ToamaisutaaSignInThrottle"/>. Implemented by the EF package.</summary>
public interface ISignInThrottleStore
{
    Task<ToamaisutaaSignInThrottle?> FindAsync(Guid userId, string source, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves the count to the new values only if the row still holds the expected ones, and answers
    /// whether it did. A missing row counts as holding zero and nulls, and is inserted.
    /// </summary>
    /// <remarks>
    /// Must be conditional: two wrong passwords landing together would otherwise be counted as one. A
    /// lost insert race answers false, and the caller reads again.
    /// </remarks>
    Task<bool> UpdateFailedAttemptsAsync(
        Guid userId,
        string source,
        int expectedFailedAttemptCount,
        DateTimeOffset? expectedFirstFailedAttemptAt,
        DateTimeOffset? expectedLockedOutUntil,
        int failedAttemptCount,
        DateTimeOffset? firstFailedAttemptAt,
        DateTimeOffset? lockedOutUntil,
        CancellationToken cancellationToken = default);

    /// <summary>Every row for the account, after a new password makes the old guesses moot.</summary>
    Task DeleteAllForUserAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes rows that count nothing any more: no lock in force and a window that closed before
    /// <paramref name="windowStartedBefore"/>.
    /// </summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, DateTimeOffset windowStartedBefore, CancellationToken cancellationToken = default);
}
