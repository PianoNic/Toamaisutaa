using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaTrustedDeviceExtensions
{
    /// <summary>
    /// Adds "remember this device": an enrolled user who completes a live two-factor challenge can
    /// skip the second factor on the same device until the trust expires.
    /// </summary>
    /// <remarks>
    /// Needs two-factor authentication and a store registration, both checked at startup. A trusted
    /// device is a cached second factor and nothing else - it never stands in for the password, and
    /// it never survives a credential change.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaTrustedDevices(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.TrustedDevicesConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaTrustedDeviceOptions>().Bind(configuration.GetSection(sectionName));

        return AddTrustedDevicesCore(services);
    }

    public static IServiceCollection AddToamaisutaaTrustedDevices(
        this IServiceCollection services,
        Action<ToamaisutaaTrustedDeviceOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaTrustedDeviceOptions>();
        services.Configure(configure);

        return AddTrustedDevicesCore(services);
    }

    private static IServiceCollection AddTrustedDevicesCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddScoped<TrustedDeviceService>();
        services.TryAddScoped<ITrustedDeviceService>(provider => provider.GetRequiredService<TrustedDeviceService>());
        services.TryAddScoped<TrustedDeviceGate>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TrustedDeviceStartupCheck>(provider =>
            new TrustedDeviceStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaTrustedDeviceOptions>>())));

        return services;
    }
}
