using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaAuthorizationExtensions
{
    /// <summary>
    /// Authenticated by default, with an optional admin role. Independent of <c>AddToamaisutaaBearer</c>.
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
    /// Registers <see cref="ICurrentUser"/>, which works without a local user table for the subject and name.
    /// </summary>
    public static IServiceCollection AddToamaisutaaCurrentUser(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // Left unbound on purpose: AddToamaisutaaAuthorization binds it, and without configuration the
        // default still avoids a missing-options failure.
        services.AddOptions<ToamaisutaaOidcOptions>();
        services.TryAddScoped<ICurrentUser, HttpContextCurrentUser>();

        return services;
    }

    /// <summary>
    /// Registers <see cref="IToamaisutaaClientConfigurationProvider"/> on its own, for an application
    /// serving the SPA configuration from its own endpoint. Already done by
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

        // Wraps whatever result handler is registered by now, so a consumer's own handler still runs.
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(AdminRoleResultHandler)))
        {
            var existing = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IAuthorizationMiddlewareResultHandler));

            services.AddSingleton<AdminRoleResultHandler>(provider => new AdminRoleResultHandler(
                provider.GetRequiredService<IOptions<ToamaisutaaAuthorizationOptions>>(),
                existing switch
                {
                    { ImplementationInstance: IAuthorizationMiddlewareResultHandler instance } => instance,
                    { ImplementationFactory: { } factory } => (IAuthorizationMiddlewareResultHandler)factory(provider),
                    { ImplementationType: { } type } => (IAuthorizationMiddlewareResultHandler)ActivatorUtilities.CreateInstance(provider, type),
                    _ => new AuthorizationMiddlewareResultHandler(),
                }));

            services.AddSingleton<IAuthorizationMiddlewareResultHandler>(provider => provider.GetRequiredService<AdminRoleResultHandler>());
        }

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

        // Ignored when no admin role is configured, so the flag alone cannot lock everyone out.
        var adminOnly = settings.RequireAdminRoleGlobally && !string.IsNullOrWhiteSpace(settings.AdminRole);

        if (adminOnly)
            fallback = fallback.RequireRole(settings.AdminRole!);

        var policy = fallback.Build();
        authorization.FallbackPolicy = policy;

        // A bare [Authorize] uses the default policy, not the fallback, so it must require the role too.
        if (adminOnly)
            authorization.DefaultPolicy = policy;
    }
}
