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

        var configured = NullIfBlank(settings.RedirectUri) ?? WithTrailingSlash(NullIfBlank(settings.PublicUrl));

        if (configured is null && !environment.IsDevelopment() && Interlocked.Exchange(ref _warnedAboutHost, 1) == 0)
        {
            logger.LogWarning(
                "Neither Oidc:PublicUrl nor Oidc:RedirectUri is set, so the redirect URI the client configuration serves "
                + "(/api/app by default) is built from the "
                + "request's Host header, which the caller controls. Set Oidc:PublicUrl.");
        }

        var redirectUri = configured ?? WithTrailingSlash(Origin(context))!;

        // Set here, not on the mapped route, so a consumer's own endpoint cannot let a shared cache
        // serve one Host-header-forged redirect URI to everybody.
        context.Response.Headers.CacheControl = "no-store";

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
