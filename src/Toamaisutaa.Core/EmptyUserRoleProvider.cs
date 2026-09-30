using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class EmptyUserRoleProvider : IUserRoleProvider
{
    public Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);
}
