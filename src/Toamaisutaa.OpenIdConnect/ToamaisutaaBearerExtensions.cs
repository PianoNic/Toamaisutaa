using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
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
        // Userinfo claims live here. An application that has registered an IDistributedCache gets a
        // shared second level for free; one that has not keeps a memory cache and the stampede
        // protection, which is the half that matters on a cold start.
        services.AddHybridCache();
        services.AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<UserInfoClaimsEnricher>();
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // Singletons because importing key material allocates a key handle and both the signing and
        // the validating path run per request. TryAdd, and AddToamaisutaaPasswordLogin adds the ring
        // too, because either call may come first - and a resource server that never issues a token
        // still has to validate the ones another instance issued.
        services.TryAddSingleton<LocalSigningKeyRing>();
        services.TryAddSingleton<LocalTokenKeys>();

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
