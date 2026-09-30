namespace Toamaisutaa.Abstractions;

/// <summary>
/// Authorization options, independent of authentication. Bound from the <c>Oidc</c> section.
/// </summary>
public sealed class ToamaisutaaAuthorizationOptions
{
    /// <summary>Authenticated by default, opt out per endpoint with <c>[AllowAnonymous]</c>.</summary>
    public bool RequireAuthenticatedUser { get; set; } = true;

    /// <summary>Role that grants administrative access. Null means no admin policy is registered
    /// at all.</summary>
    public string? AdminRole { get; set; }

    public string AdminPolicyName { get; set; } = "Toamaisutaa.Admin";

    /// <summary>Put <see cref="AdminRole"/> into the fallback and default policies, making every
    /// authorized endpoint admin-only, this package's own included. Anonymous endpoints such as
    /// <c>/auth/login</c> stay reachable.</summary>
    public bool RequireAdminRoleGlobally { get; set; }
}
