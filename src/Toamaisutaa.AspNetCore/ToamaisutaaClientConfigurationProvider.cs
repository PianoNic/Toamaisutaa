using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

internal sealed class ToamaisutaaClientConfigurationProvider(
    IOptions<ToamaisutaaOidcOptions> options,
    IHostEnvironment environment,
    ILogger<ToamaisutaaClientConfigurationProvider> logger)
    : IToamaisutaaClientConfigurationProvider
{
    private int _warnedAboutHost;

    public ToamaisutaaClientConfiguration GetConfiguration(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var settings = options.Value;

        // Explicit setting first, then the configured public URL, then whatever the request came in
        // on. The last one keeps a local run working with nothing configured at all.
        var configured = NullIfBlank(settings.RedirectUri) ?? WithTrailingSlash(NullIfBlank(settings.PublicUrl));

        if (configured is null && !environment.IsDevelopment() && Interlocked.Exchange(ref _warnedAboutHost, 1) == 0)
        {
            logger.LogWarning(
                "Neither Oidc:PublicUrl nor Oidc:RedirectUri is set, so the redirect URI in /config is built from the "
                + "request's Host header, which the caller controls. Set Oidc:PublicUrl.");
        }

        var redirectUri = configured ?? WithTrailingSlash(Origin(context))!;

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
