using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenIdConnect;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaBearerExtensions
{
    /// <summary>
    /// Validates OIDC access tokens against the configured issuer. The authorization-code flow
    /// itself belongs to the client; this is the resource-server half.
    /// </summary>
    /// <remarks>
    /// Returns the <see cref="AuthenticationBuilder"/> so an application can chain its own schemes
    /// onto it, which is how a machine-to-machine token scheme sits beside the human one.
    /// </remarks>
    public static AuthenticationBuilder AddToamaisutaaBearer(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(sectionName);

        services.AddOptions<ToamaisutaaOidcOptions>().Bind(section);
        services.AddOptions<ToamaisutaaAuthorizationOptions>().Bind(section);

        return AddBearerCore(services);
    }

    public static AuthenticationBuilder AddToamaisutaaBearer(
        this IServiceCollection services,
        Action<ToamaisutaaOidcOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaOidcOptions>();
        services.Configure(configure);
        services.AddOptions<ToamaisutaaAuthorizationOptions>();

        return AddBearerCore(services);
    }

    private static AuthenticationBuilder AddBearerCore(IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<UserInfoClaimsEnricher>();
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // Registered here because signing a token needs a JWT library and Core carries none. It
        // does nothing until password login configures a signing key.
        services.TryAddSingleton<IAccessTokenIssuer, LocalAccessTokenIssuer>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, ConfigureToamaisutaaJwtBearerOptions>());

        return services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
    }
}
