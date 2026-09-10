using Fido2NetLib;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.Passkeys;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaPasskeyExtensions
{
    /// <summary>
    /// Adds passkey registration and passwordless sign-in.
    /// </summary>
    /// <remarks>
    /// Needs a store registration, <c>Passkeys:RelyingPartyId</c> and <c>Passkeys:Origins</c>, all
    /// checked at startup rather than at the first ceremony. It also needs
    /// <c>AddToamaisutaaPasswordLogin</c>, because a passkey sign-in ends in the same locally issued
    /// token pair a password sign-in does and that is where the issuer and its keys are registered.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaPasskeys(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.PasskeysConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaPasskeyOptions>().Bind(configuration.GetSection(sectionName));

        return AddPasskeysCore(services);
    }

    public static IServiceCollection AddToamaisutaaPasskeys(
        this IServiceCollection services,
        Action<ToamaisutaaPasskeyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaPasskeyOptions>();
        services.Configure(configure);

        return AddPasskeysCore(services);
    }

    private static IServiceCollection AddPasskeysCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ToamaisutaaMetrics>();

        // Registered here as well as by password login, because either call may come first and both
        // paths mint the same session.
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.TryAddScoped<TwoFactorGate>();
        services.TryAddScoped<AuthenticationEventPublisher>();
        services.TryAddScoped<LocalSessionIssuer>();

        // A singleton because the relying party is configuration, not per-request state. Built from
        // the options rather than taken from the library's own AddFido2, so a consumer configures
        // one section and not two - and so nothing in this package depends on a registration a
        // consumer might make differently.
        services.TryAddSingleton<IFido2>(provider =>
        {
            var settings = provider.GetRequiredService<IOptions<ToamaisutaaPasskeyOptions>>().Value;

            return new Fido2(new Fido2Configuration
            {
                ServerDomain = settings.RelyingPartyId,
                ServerName = settings.RelyingPartyName ?? settings.RelyingPartyId,
                Origins = settings.Origins.ToHashSet(StringComparer.OrdinalIgnoreCase),
                Timeout = settings.TimeoutMilliseconds,
            });
        });

        services.TryAddScoped<IPasskeyService, PasskeyService>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PasskeyStartupCheck>(provider =>
            new PasskeyStartupCheck(services, provider.GetRequiredService<IOptions<ToamaisutaaPasskeyOptions>>())));

        return services;
    }
}
