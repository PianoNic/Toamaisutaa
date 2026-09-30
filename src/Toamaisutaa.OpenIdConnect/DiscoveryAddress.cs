using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Shared so the health check probes the same address the bearer handler actually uses.
/// </summary>
internal static class DiscoveryAddress
{
    public static string? For(ToamaisutaaOidcOptions settings)
    {
        var authority = NullIfBlank(settings.InternalAuthority) ?? NullIfBlank(settings.Authority);

        return authority is null ? null : From(authority);
    }

    public static string From(string authority) => $"{authority.TrimEnd('/')}/.well-known/openid-configuration";

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
