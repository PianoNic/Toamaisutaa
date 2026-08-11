namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for the local user row. Implemented by the EF package; swap it for
/// anything that can store five fields.</summary>
public interface IUserStore
{
    Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>Creates a user from a freshly mapped profile. The store assigns the key.</summary>
    Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default);

    /// <summary>Writes the profile onto an existing row. Only called when provisioning has already
    /// decided a write is warranted, so implementations do not need to compare anything.</summary>
    Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default);
}
