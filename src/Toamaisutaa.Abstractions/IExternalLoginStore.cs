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
    /// already exists, which is how a concurrent first sign-in is reported.
    /// </summary>
    Task<ToamaisutaaExternalLogin> LinkAsync(
        Guid userId,
        string providerKey,
        ExternalUserProfile profile,
        CancellationToken cancellationToken = default);

    Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default);

    /// <summary>Records the address a provider gave at a sign-in, and whether it said it verified it.</summary>
    /// <remarks>
    /// The default does nothing, so a store written before addresses were recorded keeps signing people
    /// in; its links simply never vouch for an address.
    /// </remarks>
    Task UpdateEmailAsync(Guid externalLoginId, string? email, bool emailVerified, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    /// <summary>Every provider linked to the user, oldest first.</summary>
    /// <remarks>
    /// The default throws, so a store written before linking could be listed keeps compiling and fails
    /// only where a user actually lists or removes one.
    /// </remarks>
    Task<IReadOnlyList<ToamaisutaaExternalLogin>> ListAsync(Guid userId, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            $"{GetType().Name} does not implement {nameof(IExternalLoginStore)}.{nameof(ListAsync)}, so linked providers "
            + "cannot be listed. Implement it to read ToamaisutaaExternalLogin rows by UserId.");

    /// <summary>Removes the user's link to one provider. False when there was none.</summary>
    Task<bool> DeleteAsync(Guid userId, string providerKey, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            $"{GetType().Name} does not implement {nameof(IExternalLoginStore)}.{nameof(DeleteAsync)}, so linked providers "
            + "cannot be removed. Implement it to delete ToamaisutaaExternalLogin rows by UserId and ProviderKey.");
}
