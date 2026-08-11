namespace Toamaisutaa.Abstractions;

/// <summary>
/// Everything read from the <c>Oidc</c> configuration section. Property names match the keys the
/// existing deployments already use, so adopting the package is a re-registration rather than a
/// re-keying. Shared with the interactive server-side flow when that arrives, which is why it is
/// named after OIDC and not after the bearer transport.
/// </summary>
public sealed class ToamaisutaaOidcOptions
{
    /// <summary>The issuer as the tokens see it, and what the SPA points at.</summary>
    public string? Authority { get; set; }

    /// <summary>How this process reaches the issuer for metadata discovery when that differs from
    /// the public issuer (a container on the same Docker network, a service behind a proxy).
    /// Tokens keep the public issuer; only discovery moves.</summary>
    public string? InternalAuthority { get; set; }

    public string? ClientId { get; set; }

    public bool RequireHttpsMetadata { get; set; } = true;

    public bool ValidateIssuer { get; set; } = true;

    /// <summary>On by default. Turning it off accepts any token the issuer minted for any of its
    /// clients, so it is a deliberate choice rather than a convenience.</summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>Audiences accepted when <see cref="ValidateAudience"/> is on. Falls back to
    /// <see cref="ClientId"/> when left empty.</summary>
    public IList<string> ValidAudiences { get; set; } = new List<string>();

    /// <summary>Claim type carrying the display name on the resulting identity.</summary>
    public string NameClaim { get; set; } = "name";

    /// <summary>Claim type role checks read. Issuers disagree: Keycloak publishes <c>roles</c>,
    /// while Pocket ID, Authentik and Entra publish <c>groups</c>. Reading the wrong one 403s every
    /// request while the token itself is perfectly valid.</summary>
    public string RoleClaim { get; set; } = "roles";

    /// <summary>Fetch claims the access token does not carry from the issuer's userinfo endpoint.
    /// Pocket ID, Okta and Entra keep group membership out of the access token to bound its size,
    /// so without this those deployments can never satisfy a role requirement.</summary>
    public bool FetchClaimsFromUserInfo { get; set; } = true;

    public TimeSpan UserInfoCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    // ── Served to the SPA by the configuration endpoint ──

    public string Scope { get; set; } = "openid profile email roles";

    public string? RedirectUri { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>Public base URL of the app, used to derive the redirect URIs when they are not set
    /// explicitly. One less thing to configure, and to get wrong.</summary>
    public string? PublicUrl { get; set; }

    /// <summary>Bearer token read from the query string, for handshakes that cannot carry a
    /// header.</summary>
    public ToamaisutaaQueryTokenOptions QueryToken { get; set; } = new();
}

/// <summary>
/// Browsers cannot set an <c>Authorization</c> header on a WebSocket handshake, so SignalR clients
/// pass the token as a query parameter. Reading it everywhere would put tokens in access logs for
/// no reason, so it is scoped to the paths that need it. An empty <see cref="IncludePaths"/> means
/// the feature is off; there is no separate switch, so "enabled but scoped to nothing" cannot
/// happen.
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
