using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// In Development the sample's published keys are allowed - that is what they are for - but only on
/// a server nothing else can reach.
/// </summary>
/// <remarks>
/// A Development host bound to <c>0.0.0.0</c> - a container, or a staging box started with the wrong
/// environment - is reachable, and signs tokens anyone with the public repository can forge. The
/// addresses exist only once the server has bound them, which is why this runs at
/// <see cref="IHostedLifecycleService.StartedAsync"/> rather than with the other startup checks. A
/// server that reports no addresses, such as the test server, listens on nothing to reach.
/// </remarks>
internal sealed class PublishedSecretsLoopbackCheck(IServiceProvider provider, IHostEnvironment environment, IServer server)
    : IHostedLifecycleService
{
    public Task StartedAsync(CancellationToken cancellationToken)
    {
        if (!environment.IsDevelopment())
            return Task.CompletedTask;

        var reachable = (server.Features.Get<IServerAddressesFeature>()?.Addresses ?? [])
            .Where(address => !IsLoopback(address))
            .ToList();

        if (reachable.Count == 0)
            return Task.CompletedTask;

        var problems = PublishedSecretsStartupCheck.PublishedValuesInUse(provider);

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                $"Toamaisutaa refuses to serve values from the public sample on {string.Join(", ", reachable)}, which is not "
                + "loopback. They are accepted in Development on localhost only. Bind to localhost, or generate your own:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    private static bool IsLoopback(string address)
    {
        if (!Uri.TryCreate(address.Replace("://+", "://0.0.0.0").Replace("://*", "://0.0.0.0"), UriKind.Absolute, out var uri))
            return false;

        return uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
