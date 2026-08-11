using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// No roles. A local account satisfies no role requirement until the application registers its own
/// <see cref="IUserRoleProvider"/>, because this package has no roles table and inventing one would
/// be a feature of its own.
/// </summary>
internal sealed class EmptyUserRoleProvider : IUserRoleProvider
{
    public Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);
}
