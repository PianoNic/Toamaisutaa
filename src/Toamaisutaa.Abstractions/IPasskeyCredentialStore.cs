namespace Toamaisutaa.Abstractions;

public interface IPasskeyCredentialStore
{
    /// <summary>
    /// The one lookup the sign-in path makes. Not scoped to a user, because a passwordless assertion
    /// arrives carrying a credential id and nothing else - which is what the uniqueness of
    /// <see cref="ToamaisutaaPasskeyCredential.CredentialId"/> is for.
    /// </summary>
    Task<ToamaisutaaPasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>Newest first, so the one just registered is at the top of the list somebody is
    /// looking at.</summary>
    Task<IReadOnlyList<ToamaisutaaPasskeyCredential>> ListAsync(Guid userId, CancellationToken cancellationToken = default);

    Task CreateAsync(ToamaisutaaPasskeyCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records an accepted assertion: the counter the authenticator reported, whether the credential
    /// is currently backed up, and when.
    /// </summary>
    /// <remarks>
    /// The counter is what makes a cloned authenticator detectable, so it has to be written on every
    /// success rather than left for a later save that may not happen. The backup flag is written
    /// alongside it because it changes whenever the user turns their provider's sync on or off, and
    /// this is the only moment we hear about it.
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

    Task<int> CountAsync(Guid userId, CancellationToken cancellationToken = default);
}

public interface IPasskeyChallengeStore
{
    Task CreateAsync(ToamaisutaaPasskeyChallenge challenge, CancellationToken cancellationToken = default);

    Task<ToamaisutaaPasskeyChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
