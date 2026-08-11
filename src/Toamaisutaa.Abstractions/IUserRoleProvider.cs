namespace Toamaisutaa.Abstractions;

/// <summary>
/// Roles to write into a locally issued access token. External tokens carry whatever the identity
/// provider put in them; locally issued ones have no such source, so this is where they come from.
/// </summary>
/// <remarks>
/// The shipped implementation returns nothing, which means local accounts satisfy no role
/// requirement until an application supplies its own. That is deliberate: a roles table is its own
/// feature, with assignment, storage and the question of whether local roles may augment an
/// identity provider's.
/// </remarks>
public interface IUserRoleProvider
{
    Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default);
}
