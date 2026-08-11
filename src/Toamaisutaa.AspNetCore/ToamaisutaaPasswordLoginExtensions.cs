using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.RateLimiting;
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

        services.TryAddScoped<IPasswordSignInService, PasswordSignInService>();
        services.TryAddScoped<IPasswordAccountService, PasswordAccountService>();

        services.AddRateLimiter(limiter =>
            limiter.AddPolicy<string, PasswordEndpointRateLimiterPolicy>(ToamaisutaaDefaults.PasswordEndpointRateLimitPolicy));

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
