using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Refuses requests that came from elsewhere while the sample's published keys are in use in
/// Development. The server binds to loopback behind a same-host proxy or tunnel, so the startup check
/// passes while the proxy puts the host on a public name.
/// </summary>
/// <remarks>
/// A request counts as from elsewhere when it names a host other than a loopback one, or carries a
/// forwarding header, including <c>X-Original-For</c>, which the forwarded-headers middleware leaves
/// behind when it consumes the others before this runs. Not caught: a raw TCP forwarder that keeps
/// <c>Host: localhost</c> and adds nothing, which looks exactly like a local request.
/// </remarks>
internal sealed class PublishedSecretsProxyGuard(
    IServiceProvider provider,
    IHostEnvironment environment,
    ILogger<PublishedSecretsProxyGuard> logger) : IStartupFilter
{
    private static readonly string[] ForwardingHeaders =
        ["X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Real-IP", "X-Original-For", "X-Original-Host"];

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        var published = new Lazy<bool>(() =>
            environment.IsDevelopment() && PublishedSecretsStartupCheck.PublishedValuesInUse(provider).Count > 0);

        app.Use(async (context, following) =>
        {
            if (published.Value && FromElsewhere(context.Request) is { } evidence)
            {
                logger.LogError(
                    "Refused a request that did not come from this machine ({Evidence}): this host serves values from the public "
                    + "sample, which are accepted in Development on localhost only. Generate your own keys.",
                    evidence);

                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                return;
            }

            await following(context);
        });

        next(app);
    };

    private static string? FromElsewhere(HttpRequest request)
    {
        if (ForwardingHeaders.FirstOrDefault(request.Headers.ContainsKey) is { } header)
            return $"{header} present";

        var host = request.Host.Host;

        return IsLoopbackHost(host) ? null : $"Host is {host}";
    }

    private static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address));
}
