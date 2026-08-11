using System.Security.Claims;

namespace Toamaisutaa.Abstractions;

/// <summary>
/// Runs the provisioning decision against the stores. Idempotent, and safe when two requests for a
/// never-seen subject arrive at once.
/// </summary>
public interface IExternalLoginProvisioner
{
    Task<ToamaisutaaUser> ProvisionAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);
}
