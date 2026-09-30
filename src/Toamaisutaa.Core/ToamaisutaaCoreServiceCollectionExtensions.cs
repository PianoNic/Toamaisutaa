using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers the claims mapper, the provisioning policy and the provisioner. Opt-in: the
    /// package is fully usable without a local user table.
    /// </summary>
    /// <remarks>
    /// Stores come from a separate call. Every service is registered with TryAdd, so registering
    /// your own <see cref="IClaimsProfileMapper"/> or <see cref="IProvisioningPolicy"/> first
    /// replaces the default.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaProvisioning(
        this IServiceCollection services,
        Action<ToamaisutaaProvisioningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaProvisioningOptions>();

        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IClaimsProfileMapper, DefaultClaimsProfileMapper>();
        services.TryAddSingleton<IProvisioningPolicy, DefaultProvisioningPolicy>();
        services.TryAddScoped<IExternalLoginProvisioner, ExternalLoginProvisioner>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService>(new ProvisioningStartupCheck(services)));

        return services;
    }

    /// <summary>
    /// Registers a sink that is handed every security-relevant outcome - sign-ins, lockouts,
    /// password changes, two-factor and device events - so an application can write an audit table
    /// instead of scraping its logs for one.
    /// </summary>
    /// <remarks>
    /// Additive: call it once per sink and all of them are invoked, in registration order. Scoped,
    /// so a sink can share the request's unit of work. A sink that throws, including from its
    /// constructor, is logged and stepped over rather than failing the request.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaAuthenticationEventSink<TSink>(this IServiceCollection services)
        where TSink : class, IAuthenticationEventSink
    {
        ArgumentNullException.ThrowIfNull(services);

        // TryAdd keeps a consumer's own lifetime for the sink. The publisher reads the registration
        // rather than the interface so a throwing constructor happens inside its try, not while DI
        // materialises an enumerable.
        services.TryAddScoped<TSink>();
        services.AddScoped<IAuthenticationEventSink>(provider => provider.GetRequiredService<TSink>());
        services.AddScoped(provider => new AuthenticationEventSinkRegistration(typeof(TSink), provider.GetRequiredService<TSink>));
        services.TryAddScoped<AuthenticationEventPublisher>();

        return services;
    }

    /// <summary>
    /// Runs a periodic sweep of expired token, challenge and trusted-device rows. Opt-in: without it
    /// those tables only grow, and with it this package writes to the database on a timer.
    /// </summary>
    public static IServiceCollection AddToamaisutaaTokenCleanup(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TokenCleanupService>());

        return services;
    }
}
