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
    /// Requires <c>AddToamaisutaaBearer</c> for the token validation and the issuer, a store
    /// registration for the tables, and an <see cref="IPasswordResetNotifier"/> of your own. All
    /// three are checked at startup rather than at the first request.
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

        // Local sign-in is about a local user row, so the account side is not optional here the way
        // it is for a pure resource server.
        services.AddToamaisutaaProvisioning();
        services.AddToamaisutaaCurrentUser();

        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.TryAddSingleton<IPasswordValidator, DefaultPasswordValidator>();
        services.TryAddSingleton<IUserRoleProvider, EmptyUserRoleProvider>();
        services.TryAddSingleton<DummyPasswordHash>();

        // The sign-in path always asks whether a second factor applies. Bound and registered even
        // when AddToamaisutaaTwoFactor was never called, because the gate answers "no" from the
        // absence of the stores rather than from its own absence - which would be a crash.
        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.TryAddScoped<TwoFactorGate>();

        // Same shape: the sign-in path always asks whether a device token stands in for a second
        // factor, and the gate answers no from the absence of the store rather than its own.
        services.AddOptions<ToamaisutaaTrustedDeviceOptions>();
        services.TryAddScoped<TrustedDeviceGate>();

        services.TryAddScoped<IPasswordSignInService, PasswordSignInService>();
        services.TryAddScoped<IPasswordAccountService, PasswordAccountService>();

        // Owned rather than delegated to the rate-limiting middleware, so that forgetting a call in
        // Program.cs cannot silently leave the anonymous endpoints unthrottled.
        services.TryAddSingleton<PasswordRateLimiter>();

        // A typed factory, not a plain one: TryAddEnumerable needs to know the implementation type
        // to tell this apart from every other hosted service.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PasswordLoginStartupCheck>(provider =>
            new PasswordLoginStartupCheck(
                services,
                provider.GetRequiredService<Options.IOptions<ToamaisutaaLocalLoginOptions>>(),
                provider.GetRequiredService<Options.IOptions<ToamaisutaaOidcOptions>>(),
                provider.GetRequiredService<DummyPasswordHash>())));

        return services;
    }
}
