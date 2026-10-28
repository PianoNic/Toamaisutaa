using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaExternalLoginExtensions
{
    /// <summary>
    /// Adds sign-in through the identity providers listed under <c>ExternalLogin:Providers</c>, ending in
    /// this application's own tokens. With none listed, nothing is mapped.
    /// </summary>
    /// <remarks>
    /// Needs <c>AddToamaisutaaPasswordLogin</c>, which registers the token issuer a sign-in ends in, a
    /// store registration and <c>AddToamaisutaaTokenCleanup()</c>, all checked at startup.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaExternalLogin(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.ExternalLoginConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaExternalLoginOptions>().Bind(configuration.GetSection(sectionName));

        return AddExternalLoginCore(services);
    }

    public static IServiceCollection AddToamaisutaaExternalLogin(
        this IServiceCollection services,
        Action<ToamaisutaaExternalLoginOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaExternalLoginOptions>();
        services.Configure(configure);

        return AddExternalLoginCore(services);
    }

    private static IServiceCollection AddExternalLoginCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ToamaisutaaMetrics>();

        // Registered here as well as by password login, because either call may come first and both
        // paths mint the same session.
        services.AddToamaisutaaProvisioning();
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.TryAddScoped<TwoFactorGate>();
        services.TryAddScoped<AuthenticationEventPublisher>();
        HttpContextAuthenticationActor.Register(services);
        services.TryAddScoped<LocalSessionIssuer>();

        services.AddHttpClient(ToamaisutaaDefaults.ExternalLoginHttpClientName);
        services.TryAddSingleton<ExternalProviderClient>();
        services.TryAddScoped<ExternalLoginService>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, ExternalLoginStartupCheck>(provider =>
            new ExternalLoginStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaExternalLoginOptions>>(),
                provider.GetRequiredService<IHostEnvironment>())));

        return services;
    }
}
