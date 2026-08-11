namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for the (provider, subject) to user mapping.</summary>
public interface IExternalLoginStore
{
    Task<ToamaisutaaExternalLogin?> FindAsync(
        string providerKey,
        string subject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Links a subject to a user. Throws <see cref="ExternalLoginConflictException"/> when the pair
    /// already exists, which is how a concurrent first sign-in is reported without the caller
    /// knowing anything about the storage engine.
    /// </summary>
    Task<ToamaisutaaExternalLogin> LinkAsync(
        Guid userId,
        string providerKey,
        ExternalUserProfile profile,
        CancellationToken cancellationToken = default);

    Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default);
}
