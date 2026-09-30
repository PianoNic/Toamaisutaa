namespace Toamaisutaa.Abstractions;

public interface ITwoFactorStore
{
    Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default);

    Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes a new pending enrolment, replacing one nobody has confirmed, but never one that has been.
    /// </summary>
    /// <returns>False when the stored enrolment is confirmed, including by a request that confirmed it
    /// while this one was being prepared; nothing is written then.</returns>
    /// <remarks>
    /// Must be conditional on the row still being unconfirmed in the same write: a begin that checked
    /// first and wrote later switched off a second factor confirmed in between. The default here
    /// checks and then writes, which a store that can should replace with one conditional write.
    /// </remarks>
    async Task<bool> ReplacePendingAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrolment);

        if (await FindAsync(enrolment.UserId, cancellationToken) is { ConfirmedAt: not null })
            return false;

        await UpsertAsync(enrolment, cancellationToken);
        return true;
    }

    /// <summary>
    /// Writes the secret re-encrypted under the current key, and nothing else, if it is still stored
    /// under <paramref name="expectedKeyVersion"/>.
    /// </summary>
    /// <returns>False when the row is gone or another request rewrapped or replaced it first.</returns>
    /// <remarks>
    /// Only the secret columns: a whole-row write from the verifying request puts back the used step
    /// and wrong-code count it read, which another request may have moved since, reopening a spent
    /// code. Not <see cref="ToamaisutaaUserTwoFactor.UpdatedAt"/> either, which dates the enrolment
    /// rather than its encryption. The default here reads and writes the whole row, which a store
    /// that can should replace with one conditional write of these columns.
    /// </remarks>
    async Task<bool> RewrapSecretAsync(
        Guid userId,
        string expectedKeyVersion,
        byte[] secretCiphertext,
        byte[] secretNonce,
        byte[] secretTag,
        string keyVersion,
        CancellationToken cancellationToken = default)
    {
        if (await FindAsync(userId, cancellationToken) is not { } enrolment || enrolment.EncryptionKeyVersion != expectedKeyVersion)
            return false;

        enrolment.SecretCiphertext = secretCiphertext;
        enrolment.SecretNonce = secretNonce;
        enrolment.SecretTag = secretTag;
        enrolment.EncryptionKeyVersion = keyVersion;

        await UpsertAsync(enrolment, cancellationToken);
        return true;
    }

    /// <summary>
    /// Confirms the pending enrolment, writing only <see cref="ToamaisutaaUserTwoFactor.ConfirmedAt"/>
    /// and <see cref="ToamaisutaaUserTwoFactor.UpdatedAt"/>, if it is still unconfirmed and still the
    /// one begun at <paramref name="expectedUpdatedAt"/>.
    /// </summary>
    /// <returns>False when it was confirmed, replaced by another begin, or removed first.</returns>
    /// <remarks>
    /// A whole-row write from the confirming request put back the used step it read before the code
    /// was recorded, so the code that confirmed worked again at sign-in. The default here reads and
    /// writes the whole row, which a store that can should replace with one conditional write.
    /// </remarks>
    async Task<bool> ConfirmPendingAsync(
        Guid userId,
        DateTimeOffset expectedUpdatedAt,
        DateTimeOffset confirmedAt,
        CancellationToken cancellationToken = default)
    {
        if (await FindAsync(userId, cancellationToken) is not { ConfirmedAt: null } enrolment || enrolment.UpdatedAt != expectedUpdatedAt)
            return false;

        enrolment.ConfirmedAt = confirmedAt;
        enrolment.UpdatedAt = confirmedAt;

        await UpsertAsync(enrolment, cancellationToken);
        return true;
    }

    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Records the accepted time step, which is what makes a replay fail.</summary>
    /// <returns>
    /// True only when this call moved the recorded step forward, in one write conditional on the
    /// stored step being null or lower. False when another request recorded this step, or a later
    /// one, first - which is a replay, and the code is refused.
    /// </returns>
    /// <remarks>
    /// Must be conditional: an unconditional write lets two requests with the same code both pass,
    /// and a late write move the step backwards and reopen a used code.
    /// </remarks>
    Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes the wrong-code count for an account with no password credential, in one write
    /// conditional on all three stored values still being the expected ones.
    /// </summary>
    /// <returns>False when another request changed any of them first; the caller reads again and
    /// reapplies, so parallel guesses each count rather than all writing the same number.</returns>
    /// <remarks>
    /// All three, not the count alone: a lock resets the count to zero, so a stale write conditional
    /// on the count alone could clear a lock it never saw.
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
