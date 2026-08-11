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
    /// Runs a periodic sweep of expired refresh and password-reset rows. Opt-in: without it those
    /// tables only grow, and with it this package writes to the database on a timer, which is not
    /// something to switch on for someone.
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
