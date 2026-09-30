namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for the local user row. Implemented by the EF package; swap it for
/// anything that can store five fields.</summary>
public interface IUserStore
{
    Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Best-effort lookup by email, case-insensitive; returns the first of possibly several matches.
    /// Email is a profile field, not an identity, so never use this to grant access.
    /// </summary>
    Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Creates a user from a freshly mapped profile. The store assigns the key.</summary>
    Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a user with no external identity behind it, for local registration. The caller
    /// supplies the profile fields; the store assigns the key and the timestamps.
    /// </summary>
    Task<ToamaisutaaUser> CreateAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default);

    /// <summary>Writes the profile onto an existing row. Only called when provisioning has already
    /// decided a write is warranted, so implementations do not need to compare anything.</summary>
    Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rewrites the stamp that invalidates outstanding sessions. Bumped by every credential change:
    /// a password set, change or reset, and enabling, disabling or regenerating a second factor.
    /// </summary>
    Task UpdateSecurityStampAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the user name and display name on an existing row, when completing a reserved invitation.
    /// </summary>
    Task SetUserNameAsync(Guid userId, string userName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the email on an existing row after a verified change of address, so notifiers mail the
    /// new address.
    /// </summary>
    Task SetEmailAsync(Guid userId, string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a user and everything that hangs off it. Used to undo a registration that lost a race
    /// on the credential's unique index.
    /// </summary>
    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);
}
