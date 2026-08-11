namespace Toamaisutaa.Abstractions;

/// <summary>
/// Authorization is configured separately from authentication, and neither requires the other.
/// Bound from the same <c>Oidc</c> section, because that is where these keys already live in the
/// deployments this replaces.
/// </summary>
public sealed class ToamaisutaaAuthorizationOptions
{
    /// <summary>Authenticated by default, opt out per endpoint with <c>[AllowAnonymous]</c>.</summary>
    public bool RequireAuthenticatedUser { get; set; } = true;

    /// <summary>Role that grants administrative access. Null means no admin policy is registered
    /// at all.</summary>
    public string? AdminRole { get; set; }

    public string AdminPolicyName { get; set; } = "Toamaisutaa.Admin";

    /// <summary>Put <see cref="AdminRole"/> into the fallback policy, so the whole application is
    /// admin-only rather than just the endpoints that ask for it.</summary>
    public bool RequireAdminRoleGlobally { get; set; }
}
