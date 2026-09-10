using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers the claims mapper, the provisioning policy and the provisioner. Opt-in: the
    /// package is fully usable without a local user table, which is what three of the four
    /// applications this was extracted from actually do.
    /// </summary>
    /// <remarks>
    /// Stores come from a separate call, so this may run before or after them. Every service is
    /// registered with TryAdd, so registering your own <see cref="IClaimsProfileMapper"/> or
    /// <see cref="IProvisioningPolicy"/> first replaces the default.
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
    /// Additive, not TryAdd: call it once per sink and all of them are invoked, in registration
    /// order. Scoped, so a sink can take the same unit of work the request is already using, and
    /// built on the first event of the request rather than on every request that resolves a
    /// service. Nothing else needs switching on, and a sink that throws is logged and stepped over
    /// rather than allowed to fail the request that produced the event - including a sink that
    /// throws from its own constructor.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaAuthenticationEventSink<TSink>(this IServiceCollection services)
        where TSink : class, IAuthenticationEventSink
    {
        ArgumentNullException.ThrowIfNull(services);

        // TryAdd on the sink itself, so a consumer who registered it with a lifetime of their own
        // keeps it. The interface registration is what a consumer resolving sinks directly reads;
        // the publisher reads the registration instead, so building the sink happens inside its try
        // rather than while dependency injection is materialising an enumerable.
        services.TryAddScoped<TSink>();
        services.AddScoped<IAuthenticationEventSink>(provider => provider.GetRequiredService<TSink>());
        services.AddScoped(provider => new AuthenticationEventSinkRegistration(typeof(TSink), provider.GetRequiredService<TSink>));
        services.TryAddScoped<AuthenticationEventPublisher>();

        return services;
    }

    /// <summary>
    /// Runs a periodic sweep of expired refresh, password-reset and invitation rows, plus the
    /// two-factor challenge and trusted-device rows when those are configured. Opt-in: without it
    /// those tables only grow, and with it this package writes to the database on a timer, which is
    /// not something to switch on for someone.
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
