using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// A warning rather than a refusal, because many providers issue access tokens whose only audience
/// is the client id, which is also the audience of every unmarked ID token.
/// </summary>
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
