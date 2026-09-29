using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Says so at startup when provider tokens are checked against the client id rather than an API
/// audience.
/// </summary>
/// <remarks>
/// The client id is the audience of every ID token the provider issues to that client, so under
/// the fallback an ID token passes audience validation. The package refuses the ones that are marked
/// as ID tokens; one that carries no marker cannot be told apart, and only a real API audience keeps
/// it out. A warning rather than a refusal, because plenty of providers issue access tokens whose
/// only audience is the client id, and refusing to start would break every one of them.
/// </remarks>
internal sealed class AudienceStartupWarning(
    IOptions<ToamaisutaaOidcOptions> options,
    ILogger<AudienceStartupWarning> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;

        if (!string.IsNullOrWhiteSpace(settings.Authority)
            && settings.ValidateAudience
            && settings.ValidAudiences.Count == 0
            && !string.IsNullOrWhiteSpace(settings.ClientId))
        {
            logger.LogWarning(
                "Oidc:ValidAudiences is empty, so provider tokens are checked against the client id {ClientId}. "
                + "That is also the audience of every ID token issued to this client, and an ID token without an "
                + "ID-token marker cannot be refused. Set Oidc:ValidAudiences to your API's own audience if your "
                + "provider can issue one.",
                settings.ClientId);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
