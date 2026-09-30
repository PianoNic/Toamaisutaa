namespace Toamaisutaa.Abstractions;

/// <summary>
/// Everything read from the <c>Oidc</c> configuration section.
/// </summary>
public sealed class ToamaisutaaOidcOptions
{
    /// <summary>The issuer as the tokens see it, and what the SPA points at.</summary>
    public string? Authority { get; set; }

    /// <summary>How this process reaches the issuer for metadata discovery when that differs from
    /// the public issuer. Tokens keep the public issuer; only discovery moves.</summary>
    public string? InternalAuthority { get; set; }

    public string? ClientId { get; set; }

    public bool RequireHttpsMetadata { get; set; } = true;

    public bool ValidateIssuer { get; set; } = true;

    /// <summary>On by default. Turning it off accepts any token the issuer minted for any of its
    /// clients.</summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>Audiences accepted when <see cref="ValidateAudience"/> is on. Falls back to
    /// <see cref="ClientId"/> when left empty.</summary>
    public IList<string> ValidAudiences { get; set; } = new List<string>();

    /// <summary>Claim type carrying the display name on the resulting identity.</summary>
    public string NameClaim { get; set; } = "name";

    /// <summary>Claim type role checks read. Keycloak publishes <c>roles</c>, while Pocket ID,
    /// Authentik and Entra publish <c>groups</c>; reading the wrong one 403s every request.</summary>
    public string RoleClaim { get; set; } = "roles";

    /// <summary>Fetch claims the access token does not carry from the issuer's userinfo endpoint.
    /// Pocket ID, Okta and Entra keep group membership out of the access token, so without this
    /// they can never satisfy a role requirement.</summary>
    public bool FetchClaimsFromUserInfo { get; set; } = true;

    public TimeSpan UserInfoCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Off by default. Turning it on lets the userinfo cache use the application's
    /// <c>IDistributedCache</c> as a second level, which also puts authorization claims and personal
    /// data into a store this package does not own.</summary>
    public bool ShareUserInfoCacheAcrossInstances { get; set; }

    public string Scope { get; set; } = "openid profile email roles";

    public string? RedirectUri { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>Public base URL of the app, used to derive the redirect URIs when they are not set
    /// explicitly.</summary>
    public string? PublicUrl { get; set; }

    /// <summary>Bearer token read from the query string, for handshakes that cannot carry a
    /// header.</summary>
    public ToamaisutaaQueryTokenOptions QueryToken { get; set; } = new();

    /// <summary>What the discovery health check probes with, when one is registered.</summary>
    public ToamaisutaaDiscoveryHealthCheckOptions HealthCheck { get; set; } = new();
}

/// <summary>
/// Tunes the health check <c>AddToamaisutaaHealthChecks()</c> registers, which probes
/// <see cref="ToamaisutaaOidcOptions.Authority"/> or
/// <see cref="ToamaisutaaOidcOptions.InternalAuthority"/>.
/// </summary>
public sealed class ToamaisutaaDiscoveryHealthCheckOptions
{
    /// <summary>How long a successful fetch is trusted before the check reaches for the issuer
    /// again, so frequent readiness probes do not load the issuer.</summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long a single fetch is given before it counts as unreachable.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How long an unreachable issuer stays degraded, measured from the last fetch that
    /// succeeded, before the check reports unhealthy. Degraded answers 200, so without this bound an
    /// instance would stay in rotation however long the issuer stayed gone.
    /// <see cref="TimeSpan.Zero"/> reports unhealthy on the first failure.</summary>
    public TimeSpan DegradedFor { get; set; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// Bearer token read from the query string, for WebSocket handshakes that cannot set an
/// <c>Authorization</c> header. Scoped to <see cref="IncludePaths"/> to keep tokens out of access
/// logs elsewhere; an empty <see cref="IncludePaths"/> means the feature is off.
/// </summary>
public sealed class ToamaisutaaQueryTokenOptions
{
    public string ParameterName { get; set; } = "access_token";

    /// <summary>Path prefixes the query token is honoured on, for example <c>/hubs</c>.</summary>
    public IList<string> IncludePaths { get; set; } = new List<string>();

    /// <summary>Path prefixes carved back out of <see cref="IncludePaths"/>, for a hub that
    /// authenticates something other than an OIDC token on its own.</summary>
    public IList<string> ExcludePaths { get; set; } = new List<string>();
}
