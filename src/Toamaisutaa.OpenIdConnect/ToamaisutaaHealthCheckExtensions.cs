using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenIdConnect;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaHealthCheckExtensions
{
    /// <summary>
    /// Probes the issuer discovery document the bearer handler validates against. Unhealthy when it
    /// cannot be fetched at all, degraded once a cached document is being served past its refresh
    /// interval, healthy otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Call it after <c>AddToamaisutaaBearer</c>, which is what binds the <c>Oidc</c> section this
    /// reads. Without an issuer the check reports unhealthy and names the two keys it looked at,
    /// because an application with no issuer has nothing for this to probe.
    /// </para>
    /// <para>
    /// Returns the <see cref="IHealthChecksBuilder"/> so an application can chain its own checks
    /// onto it, the way <c>AddToamaisutaaBearer</c> returns the authentication builder. Tagged
    /// <c>toamaisutaa</c>, <c>oidc</c> and <c>ready</c>, so a readiness endpoint can select it
    /// without naming it.
    /// </para>
    /// </remarks>
    public static IHealthChecksBuilder AddToamaisutaaHealthChecks(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaOidcOptions>();
        services.AddHttpClient(ToamaisutaaDefaults.DiscoveryHttpClientName);
        services.TryAddSingleton(TimeProvider.System);

        // A singleton the registration resolves rather than a type the health check service
        // activates per probe: the check remembers its last successful fetch, and an instance per
        // probe would forget it and never report degraded.
        services.TryAddSingleton<DiscoveryHealthCheck>();

        return services.AddHealthChecks().Add(new HealthCheckRegistration(
            ToamaisutaaDefaults.DiscoveryHealthCheckName,
            provider => provider.GetRequiredService<DiscoveryHealthCheck>(),
            failureStatus: null,
            tags: ["toamaisutaa", "oidc", "ready"]));
    }
}
