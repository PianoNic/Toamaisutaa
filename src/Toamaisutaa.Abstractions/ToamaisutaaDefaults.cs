namespace Toamaisutaa.Abstractions;

/// <summary>Names Toamaisutaa uses when nothing else is configured.</summary>
public static class ToamaisutaaDefaults
{
    /// <summary>Identifies the provider on an external login row. Equals the bearer scheme name,
    /// so a single-provider deployment never has to think about it.</summary>
    public const string ProviderKey = "Bearer";

    /// <summary>Named <c>HttpClient</c> the userinfo enrichment resolves.</summary>
    public const string UserInfoHttpClientName = "toamaisutaa-userinfo";

    /// <summary>Where the SPA's runtime configuration is served from.</summary>
    public const string ConfigurationEndpointPattern = "/api/app";

    /// <summary>Configuration section every options type binds from.</summary>
    public const string ConfigurationSection = "Oidc";

    /// <summary>Configuration section local password login binds from.</summary>
    public const string LocalLoginConfigurationSection = "LocalLogin";

    /// <summary>Key id stamped on the local signing key, so the bearer layer can tell it apart from
    /// the identity provider's keys and refuse to validate one issuer's tokens with the other's
    /// key.</summary>
    public const string LocalSigningKeyId = "toamaisutaa-local";

    /// <summary>Rate-limiting policy applied to the unauthenticated password endpoints.</summary>
    public const string PasswordEndpointRateLimitPolicy = "Toamaisutaa.PasswordEndpoints";
}
