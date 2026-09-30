namespace Toamaisutaa.Abstractions;

/// <summary>
/// Roles to write into a locally issued access token.
/// </summary>
/// <remarks>
/// The shipped implementation returns nothing, so local accounts satisfy no role requirement until
/// an application supplies its own.
/// </remarks>
public interface IUserRoleProvider
{
    Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default);
}
