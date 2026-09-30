using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenIdConnect;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaHealthCheckExtensions
{
    /// <summary>
    /// Probes the issuer discovery document the bearer handler validates against. Degraded while the
    /// last successful fetch is younger than <c>Oidc:HealthCheck:DegradedFor</c>, unhealthy after that
    /// or when it was never fetched.
    /// </summary>
    /// <remarks>
    /// Call it after <c>AddToamaisutaaBearer</c>, which binds the <c>Oidc</c> section this reads.
    /// Tagged <c>toamaisutaa</c>, <c>oidc</c> and <c>ready</c>.
    /// </remarks>
    public static IHealthChecksBuilder AddToamaisutaaHealthChecks(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaOidcOptions>();
        services.AddHttpClient(ToamaisutaaDefaults.DiscoveryHttpClientName);
        services.TryAddSingleton(TimeProvider.System);

        // Resolved as a singleton rather than activated per probe, or it forgets its last fetch and never reports degraded.
        services.TryAddSingleton<DiscoveryHealthCheck>();

        return services.AddHealthChecks().Add(new HealthCheckRegistration(
            ToamaisutaaDefaults.DiscoveryHealthCheckName,
            provider => provider.GetRequiredService<DiscoveryHealthCheck>(),
            failureStatus: null,
            tags: ["toamaisutaa", "oidc", "ready"]));
    }
}
