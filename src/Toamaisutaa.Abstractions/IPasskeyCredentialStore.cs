namespace Toamaisutaa.Abstractions;

public interface IPasskeyCredentialStore
{
    /// <summary>
    /// Not scoped to a user, because a passwordless assertion arrives carrying a credential id and
    /// nothing else.
    /// </summary>
    Task<ToamaisutaaPasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>Newest first.</summary>
    Task<IReadOnlyList<ToamaisutaaPasskeyCredential>> ListAsync(Guid userId, CancellationToken cancellationToken = default);

    Task CreateAsync(ToamaisutaaPasskeyCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records an accepted assertion: the counter the authenticator reported, whether the credential
    /// is currently backed up, and when.
    /// </summary>
    /// <remarks>
    /// The counter is what makes a cloned authenticator detectable, so it must be written on every
    /// success rather than left for a later save that may not happen.
    /// </remarks>
    Task RecordUseAsync(
        Guid credentialId,
        long signCount,
        bool isBackedUp,
        DateTimeOffset usedAt,
        CancellationToken cancellationToken = default);

    /// <summary>False when the credential does not exist or belongs to someone else - the same
    /// answer, so that this cannot be used to discover another account's credential ids.</summary>
    Task<bool> DeleteAsync(Guid userId, Guid credentialId, CancellationToken cancellationToken = default);

    /// <summary>Deletes every credential on the account and answers how many there were.</summary>
    /// <remarks>
    /// Called wherever trusted devices are revoked, because a remediation that leaves a passkey
    /// standing has not remediated anything.
    /// </remarks>
    Task<int> DeleteAllAsync(Guid userId, CancellationToken cancellationToken = default);

    Task<int> CountAsync(Guid userId, CancellationToken cancellationToken = default);
}

public interface IPasskeyChallengeStore
{
    Task CreateAsync(ToamaisutaaPasskeyChallenge challenge, CancellationToken cancellationToken = default);

    Task<ToamaisutaaPasskeyChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the challenge in one conditional write. True only when this call spent it;
    /// false when another request already had.</summary>
    Task<bool> MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
