using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

internal sealed class ToamaisutaaClientConfigurationProvider(IOptions<ToamaisutaaOidcOptions> options)
    : IToamaisutaaClientConfigurationProvider
{
    public ToamaisutaaClientConfiguration GetConfiguration(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var settings = options.Value;

        // Explicit setting first, then the configured public URL, then whatever the request came in
        // on. The last one keeps a local run working with nothing configured at all.
        var redirectUri =
            NullIfBlank(settings.RedirectUri)
            ?? WithTrailingSlash(NullIfBlank(settings.PublicUrl))
            ?? WithTrailingSlash(Origin(context))!;

        return new ToamaisutaaClientConfiguration
        {
            Authority = settings.Authority ?? string.Empty,
            ClientId = settings.ClientId ?? string.Empty,
            RedirectUri = redirectUri,
            PostLogoutRedirectUri = NullIfBlank(settings.PostLogoutRedirectUri) ?? redirectUri,
            Scope = settings.Scope,
        };
    }

    private static string Origin(HttpContext context) =>
        $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";

    private static string? WithTrailingSlash(string? value) =>
        value is null ? null : value.EndsWith('/') ? value : value + "/";

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
