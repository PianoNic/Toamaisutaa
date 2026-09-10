using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Scoped, so the provisioned row is resolved once per request no matter how many callers ask for
/// it. The provisioner is resolved lazily rather than injected, because <see cref="ICurrentUser"/>
/// is useful for <see cref="Subject"/> and <see cref="Name"/> alone in an application that has no
/// local user table.
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
    /// The configured claim first, then <see cref="ClaimTypes.Role"/> - the same fallback
    /// <see cref="Subject"/> and <see cref="Name"/> make, and for the same reason: a principal that
    /// did not come from this package's bearer pipeline carries the .NET type instead, and that is
    /// also the one <c>RequireRole</c> would have read there.
    /// </summary>
    public IReadOnlyList<string> Roles
    {
        get
        {
            var principal = Principal;
            if (principal is null)
                return [];

            var roles = new List<string>();

            Collect(roles, principal, oidcOptions.Value.RoleClaim);
            Collect(roles, principal, ClaimTypes.Role);

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

        // The second of the two places the stamp is enforced, and again only because the read has
        // already happened. The claim is only on locally issued tokens; a token from an identity
        // provider carries no stamp, and there is nothing to check.
        var presented = Find(ToamaisutaaDefaults.SecurityStampClaim);

        if (presented is not null && !string.Equals(presented, user.SecurityStamp, StringComparison.Ordinal))
        {
            throw new SecurityStampChangedException(
                "This token was issued before a credential on the account changed. Refresh, or sign in again.");
        }

        return _provisioned = user;
    }

    private string? Find(string claimType)
    {
        var principal = Principal;
        if (principal is null)
            return null;

        foreach (var claim in principal.FindAll(claimType))
        {
            if (!string.IsNullOrWhiteSpace(claim.Value))
                return claim.Value;
        }

        return null;
    }

    // Deduplicated because the two claim types can name the same thing - a role claim configured as
    // ClaimTypes.Role, or a principal enriched from userinfo with what the token already carried.
    private static void Collect(List<string> roles, ClaimsPrincipal principal, string claimType)
    {
        foreach (var claim in principal.FindAll(claimType))
        {
            if (!string.IsNullOrWhiteSpace(claim.Value) && !roles.Contains(claim.Value, StringComparer.Ordinal))
                roles.Add(claim.Value);
        }
    }
}
