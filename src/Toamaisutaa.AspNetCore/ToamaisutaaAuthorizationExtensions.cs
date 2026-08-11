using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaAuthorizationExtensions
{
    /// <summary>
    /// Authenticated by default, with an optional admin role. Independent of
    /// <c>AddToamaisutaaBearer</c>: an application can authenticate however it likes and still use
    /// this, or use the bearer layer and write its own policies.
    /// </summary>
    public static IServiceCollection AddToamaisutaaAuthorization(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaAuthorizationOptions>().Bind(configuration.GetSection(sectionName));
        services.AddOptions<ToamaisutaaOidcOptions>().Bind(configuration.GetSection(sectionName));

        return AddAuthorizationCore(services);
    }

    public static IServiceCollection AddToamaisutaaAuthorization(
        this IServiceCollection services,
        Action<ToamaisutaaAuthorizationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaAuthorizationOptions>();
        services.Configure(configure);

        return AddAuthorizationCore(services);
    }

    /// <summary>
    /// Registers <see cref="ICurrentUser"/>. Separate call, because provisioning is opt-in and
    /// because an application with no local user table still wants the subject and actor name.
    /// </summary>
    public static IServiceCollection AddToamaisutaaCurrentUser(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.AddOptions<ToamaisutaaProvisioningOptions>();
        services.TryAddScoped<ICurrentUser, HttpContextCurrentUser>();

        return services;
    }

    /// <summary>
    /// Registers <see cref="IToamaisutaaClientConfigurationProvider"/> on its own, for an
    /// application that composes the SPA configuration into an endpoint of its own rather than
    /// using <c>MapToamaisutaaConfiguration</c>. Already done by
    /// <see cref="AddToamaisutaaAuthorization(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    public static IServiceCollection AddToamaisutaaClientConfiguration(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaOidcOptions>();
        services.TryAddSingleton<IToamaisutaaClientConfigurationProvider, ToamaisutaaClientConfigurationProvider>();

        return services;
    }

    private static IServiceCollection AddAuthorizationCore(IServiceCollection services)
    {
        services.AddToamaisutaaClientConfiguration();

        services.AddAuthorization();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<AuthorizationOptions>, ConfigureToamaisutaaAuthorizationOptions>());

        return services;
    }
}

internal sealed class ConfigureToamaisutaaAuthorizationOptions(IOptions<ToamaisutaaAuthorizationOptions> options)
    : IConfigureOptions<AuthorizationOptions>
{
    public void Configure(AuthorizationOptions authorization)
    {
        var settings = options.Value;

        if (!string.IsNullOrWhiteSpace(settings.AdminRole))
        {
            authorization.AddPolicy(
                settings.AdminPolicyName,
                policy => policy.RequireAuthenticatedUser().RequireRole(settings.AdminRole));
        }

        if (!settings.RequireAuthenticatedUser)
            return;

        var fallback = new AuthorizationPolicyBuilder().RequireAuthenticatedUser();

        // The whole application behind one role, rather than per endpoint. Ignored when no admin
        // role is configured, so turning the flag on alone cannot lock everyone out.
        if (settings.RequireAdminRoleGlobally && !string.IsNullOrWhiteSpace(settings.AdminRole))
            fallback = fallback.RequireRole(settings.AdminRole);

        authorization.FallbackPolicy = fallback.Build();
    }
}
