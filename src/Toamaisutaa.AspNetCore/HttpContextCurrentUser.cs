using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// The provisioner is resolved lazily rather than injected, because an application with no local
/// user table still uses <see cref="Subject"/> and <see cref="Name"/>.
/// </summary>
internal sealed class HttpContextCurrentUser(
    IHttpContextAccessor accessor,
    IServiceProvider services,
    IOptions<ToamaisutaaProvisioningOptions> options,
    IOptions<ToamaisutaaOidcOptions> oidcOptions) : ICurrentUser
{
    private ToamaisutaaUser? _provisioned;

    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;

    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true;

    public string? Subject => Find(options.Value.ClaimNames.Subject) ?? Find(ClaimTypes.NameIdentifier);

    public string? Name =>
        Find(options.Value.ClaimNames.UserName)
        ?? Find(options.Value.ClaimNames.DisplayName)
        ?? Find(ClaimTypes.Name)
        ?? Find(options.Value.ClaimNames.Email)
        ?? Find(ClaimTypes.Email);

    /// <summary>
    /// Reads each identity's own role claim type, as <c>RequireRole</c> does, so this never reports a
    /// role that <c>[Authorize]</c> would refuse.
    /// </summary>
    public IReadOnlyList<string> Roles
    {
        get
        {
            var principal = Principal;
            if (principal is null)
                return [];

            var roles = new List<string>();

            Collect(roles, principal.FindAll(oidcOptions.Value.RoleClaim));

            foreach (var identity in principal.Identities)
                Collect(roles, identity.FindAll(identity.RoleClaimType));

            return roles;
        }
    }

    public bool IsInRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

    public string? FindClaim(string type) => Find(type);

    public async Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default)
    {
        if (_provisioned is not null)
            return _provisioned;

        var principal = Principal;
        if (principal is null || principal.Identity?.IsAuthenticated != true)
            throw new InvalidOperationException("There is no authenticated user on this request.");

        var provisioner = services.GetService<IExternalLoginProvisioner>()
            ?? throw new InvalidOperationException(
                "Provisioning is not registered, so there is no local user to return. "
                + "Call AddToamaisutaaProvisioning() together with a store registration, or use "
                + "ICurrentUser.Subject and ICurrentUser.Name instead.");

        var user = await provisioner.ProvisionAsync(principal, cancellationToken);

        // Only locally issued tokens carry a stamp; an identity-provider token has nothing to check.
        var presented = Find(ToamaisutaaDefaults.SecurityStampClaim);

        if (presented is not null && !string.Equals(presented, user.SecurityStamp, StringComparison.Ordinal))
        {
            throw new SecurityStampChangedException(
                "This token was issued before a credential on the account changed. Refresh, or sign in again.");
        }

        return _provisioned = user;
    }

    private string? Find(string claimType) =>
        Principal?.FindAll(claimType).FirstOrDefault(claim => !string.IsNullOrWhiteSpace(claim.Value))?.Value;

    private static void Collect(List<string> roles, IEnumerable<Claim> claims)
    {
        foreach (var claim in claims)
        {
            if (!string.IsNullOrWhiteSpace(claim.Value) && !roles.Contains(claim.Value, StringComparer.Ordinal))
                roles.Add(claim.Value);
        }
    }
}
