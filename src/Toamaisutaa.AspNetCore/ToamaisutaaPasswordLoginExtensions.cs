using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaPasswordLoginExtensions
{
    /// <summary>
    /// Adds local username and password sign-in. OIDC is the recommended path; this is for
    /// deployments that cannot run an identity provider.
    /// </summary>
    /// <remarks>
    /// Requires <c>AddToamaisutaaBearer</c>, a store registration, and an
    /// <see cref="IPasswordResetNotifier"/> of your own, all checked at startup.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaPasswordLogin(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.LocalLoginConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaLocalLoginOptions>().Bind(configuration.GetSection(sectionName));

        return AddPasswordLoginCore(services);
    }

    public static IServiceCollection AddToamaisutaaPasswordLogin(
        this IServiceCollection services,
        Action<ToamaisutaaLocalLoginOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.Configure(configure);

        return AddPasswordLoginCore(services);
    }

    private static IServiceCollection AddPasswordLoginCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.AddToamaisutaaProvisioning();
        services.AddToamaisutaaCurrentUser();

        services.TryAddSingleton<ToamaisutaaMetrics>();

        // Also added by AddToamaisutaaBearer; the startup check below needs it whichever call comes first.
        services.TryAddSingleton<LocalSigningKeyRing>();

        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.TryAddSingleton<IPasswordValidator, DefaultPasswordValidator>();
        services.TryAddSingleton<IUserRoleProvider, EmptyUserRoleProvider>();
        services.TryAddSingleton<DummyPasswordHash>();

        // Registered even without AddToamaisutaaTwoFactor: the sign-in path always resolves the gates,
        // which answer "no" from the absence of the stores rather than crashing on their own absence.
        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.TryAddScoped<TwoFactorGate>();

        services.AddOptions<ToamaisutaaTrustedDeviceOptions>();
        services.TryAddScoped<TrustedDeviceGate>();

        services.TryAddScoped<AuthenticationEventPublisher>();

        // Also registered by the passkey package, because either call may come first.
        services.TryAddScoped<LocalSessionIssuer>();

        services.TryAddScoped<IPasswordSignInService, PasswordSignInService>();
        services.TryAddScoped<IPasswordAccountService, PasswordAccountService>();

        services.TryAddScoped<ISessionService, SessionService>();

        services.TryAddSingleton<PasswordRateLimiter>();

        services.TryAddSingleton<MailRequestCooldown>();
        services.TryAddSingleton<MailRequestQueue>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, MailRequestQueue>(
            provider => provider.GetRequiredService<MailRequestQueue>()));

        // A typed factory: TryAddEnumerable needs the implementation type to tell hosted services apart.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PasswordLoginStartupCheck>(provider =>
            new PasswordLoginStartupCheck(
                services,
                provider.GetRequiredService<Options.IOptions<ToamaisutaaLocalLoginOptions>>(),
                provider.GetRequiredService<Options.IOptions<ToamaisutaaOidcOptions>>(),
                provider.GetRequiredService<DummyPasswordHash>(),
                provider.GetRequiredService<LocalSigningKeyRing>())));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PublishedSecretsStartupCheck>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Toamaisutaa.OpenIdConnect.PublishedSecretsLoopbackCheck>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Microsoft.AspNetCore.Hosting.IStartupFilter, Toamaisutaa.OpenIdConnect.PublishedSecretsProxyGuard>());

        return services;
    }
}
