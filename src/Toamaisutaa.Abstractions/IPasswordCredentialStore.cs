namespace Toamaisutaa.Abstractions;

public interface IPasswordCredentialStore
{
    Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Looks up by normalised user name, then normalised email. One call, because the
    /// login form takes one box.</summary>
    Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default);

    /// <summary>Email only, for password reset, where matching a user name would send a link to an
    /// address the caller did not name.</summary>
    Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);

    /// <summary>Throws <see cref="PasswordIdentifierConflictException"/> when the normalised user
    /// name or email is already held by another credential.</summary>
    Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);

    Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);
}

/// <summary>
/// The normalised user name or email is taken. Translated by the store from whatever its unique
/// index raised, so the flows above it never see a storage-specific exception.
/// </summary>
public sealed class PasswordIdentifierConflictException : Exception
{
    public PasswordIdentifierConflictException(Exception? innerException = null)
        : base("A local account already uses that user name or email address.", innerException)
    {
    }
}
