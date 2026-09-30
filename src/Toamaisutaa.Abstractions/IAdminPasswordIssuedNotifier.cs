namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a password an admin caused to exist through
/// <see cref="IPasswordAccountService.AdminCreateAccountAsync"/> or
/// <see cref="IPasswordAccountService.AdminSetPasswordAsync"/>, typed or generated. The package ships
/// no implementation.
/// </summary>
/// <remarks>
/// Optional: only the two admin-provisioning methods need it, and they throw if it is missing.
/// </remarks>
public interface IAdminPasswordIssuedNotifier
{
    /// <summary>
    /// Called with the raw password, the only moment it exists in the clear. <b>Never</b> called for
    /// a password a person chose for themselves.
    /// </summary>
    Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default);
}
