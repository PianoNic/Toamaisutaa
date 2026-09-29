namespace Toamaisutaa.Abstractions;

public interface ITwoFactorStore
{
    Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default);

    Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default);

    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Records the accepted time step, which is what makes a replay fail.</summary>
    /// <returns>
    /// True only when this call moved the recorded step forward, in one write conditional on the
    /// stored step being null or lower. False when another request recorded this step, or a later
    /// one, first - which is a replay, and the code is refused.
    /// </returns>
    /// <remarks>
    /// An unconditional write let two requests with the same code both pass, and let a late write
    /// move the step backwards and open a used code again.
    /// </remarks>
    Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes the wrong-code count for an account with no password credential, in one write
    /// conditional on all three stored values still being the expected ones.
    /// </summary>
    /// <returns>False when another request changed any of them first; the caller reads again and
    /// reapplies, so parallel guesses each count rather than all writing the same number.</returns>
    /// <remarks>
    /// All three, not the count alone: a lock resets the count to zero, so a request that read the
    /// row before any failure sees the count it expects after the lock, and a write conditional on
    /// the count alone lands - clearing the lock it never saw.
    /// </remarks>
    Task<bool> UpdateFailedAttemptsAsync(
        Guid userId,
        int expectedFailedAttemptCount,
        DateTimeOffset? expectedFirstFailedAttemptAt,
        DateTimeOffset? expectedLockedOutUntil,
        int failedAttemptCount,
        DateTimeOffset? firstFailedAttemptAt,
        DateTimeOffset? lockedOutUntil,
        CancellationToken cancellationToken = default);
}

public interface IRecoveryCodeStore
{
    /// <summary>Replaces the whole set. Regenerating must invalidate every previous code, not add
    /// to them.</summary>
    Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default);

    Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the code in one conditional write. True only when this call spent it; false
    /// when another request already had.</summary>
    Task<bool> MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default);
}

public interface ITwoFactorChallengeStore
{
    Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default);

    Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the challenge in one conditional write. True only when this call spent it;
    /// false when another request already had.</summary>
    Task<bool> MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
