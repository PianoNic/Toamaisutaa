namespace Toamaisutaa.Abstractions;

public interface IPasswordCredentialStore
{
    Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Looks up by normalised user name, then normalised email.</summary>
    Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default);

    /// <summary>Email only, for password reset, where matching a user name would send a link to an
    /// address the caller did not name.</summary>
    Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);

    /// <summary>Throws <see cref="PasswordIdentifierConflictException"/> when the normalised user
    /// name or email is already held by another credential.</summary>
    Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes what changed since the credential was read. Throws
    /// <see cref="CredentialConcurrencyException"/> when the row has moved underneath it since then,
    /// and leaves the next <see cref="FindByUserIdAsync"/> answering with what the row holds now.
    /// </summary>
    /// <remarks>
    /// A store that writes blindly loses concurrent changes: failed-attempt counts that never reach
    /// the lockout, and a stale sign-in writing an old hash back over a reset.
    /// </remarks>
    Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);
}

/// <summary>
/// The credential changed between being read and being written. The flows above the store read it
/// again and reapply their change, so one never silently undoes another.
/// </summary>
public sealed class CredentialConcurrencyException : Exception
{
    public CredentialConcurrencyException(Exception? innerException = null)
        : base("The password credential was changed by another request while this one was using it.", innerException)
    {
    }
}

/// <summary>
/// The normalised user name or email is taken. Stores translate their unique-index violation into this.
/// </summary>
public sealed class PasswordIdentifierConflictException : Exception
{
    public PasswordIdentifierConflictException(Exception? innerException = null)
        : base("A local account already uses that user name or email address.", innerException)
    {
    }
}
