namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for the local user row. Implemented by the EF package; swap it for
/// anything that can store five fields.</summary>
public interface IUserStore
{
    Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Best-effort lookup by email, case-insensitive. May match more than one row, because the
    /// model is multi-provider and email is a profile field rather than an identity - the first
    /// match is returned. Used to tell "no such person" apart from "that person is owned by an
    /// identity provider" in the password-reset log, and for nothing that grants access.
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
    /// Sets the user name - and, alongside it, the display name - on an existing row. For completing
    /// a reserved invitation: the row was created with only an email, and the person chooses their
    /// own user name when they finish registering.
    /// </summary>
    Task SetUserNameAsync(Guid userId, string userName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a user and everything that hangs off it. Used to take back a row created moments ago
    /// for a registration that then lost a race on the credential's unique index, so a failed
    /// attempt does not leave an account behind that nobody can sign in to.
    /// </summary>
    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);
}
