using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Refuses requests that came through a reverse proxy while the sample's published keys are in use in
/// Development. The server binds to loopback behind a same-host proxy, so the startup check passes
/// while the proxy puts the host on a public name.
/// </summary>
internal sealed class PublishedSecretsProxyGuard(
    IServiceProvider provider,
    IHostEnvironment environment,
    ILogger<PublishedSecretsProxyGuard> logger) : IStartupFilter
{
    private static readonly string[] ForwardingHeaders = ["X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Real-IP"];

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        var published = new Lazy<bool>(() =>
            environment.IsDevelopment() && PublishedSecretsStartupCheck.PublishedValuesInUse(provider).Count > 0);

        app.Use(async (context, following) =>
        {
            if (published.Value && ForwardingHeaders.FirstOrDefault(context.Request.Headers.ContainsKey) is { } header)
            {
                logger.LogError(
                    "Refused a request that arrived through a proxy ({Header} present): this host serves values from the public "
                    + "sample, which are accepted in Development on localhost only. Generate your own keys.",
                    header);

                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                return;
            }

            await following(context);
        });

        next(app);
    };
}
