using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Where this process fetches the issuer's discovery document from. One place, because the health
/// check has to probe the address the bearer handler actually uses - a check that derives its own
/// would go green against something nobody validates tokens with.
/// </summary>
internal static class DiscoveryAddress
{
    /// <summary>Null when no issuer is configured at all, which is the shape of an application that
    /// only validates tokens it issued itself.</summary>
    public static string? For(ToamaisutaaOidcOptions settings)
    {
        var authority = NullIfBlank(settings.InternalAuthority) ?? NullIfBlank(settings.Authority);

        return authority is null ? null : From(authority);
    }

    public static string From(string authority) => $"{authority.TrimEnd('/')}/.well-known/openid-configuration";

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
