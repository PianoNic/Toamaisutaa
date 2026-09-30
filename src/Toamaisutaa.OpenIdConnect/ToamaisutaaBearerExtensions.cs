using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
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
    /// Returns the <see cref="AuthenticationBuilder"/> so an application can chain its own schemes.
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
        // HybridCache for its stampede protection on userinfo; the distributed level stays off unless
        // Oidc:ShareUserInfoCacheAcrossInstances says so, because these entries decide authorization.
        services.AddHybridCache();
        services.AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<UserInfoClaimsEnricher>();
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // Also added by AddToamaisutaaPasswordLogin, since either may come first and a resource server
        // that never issues a token still validates ones another instance issued.
        services.TryAddSingleton<LocalSigningKeyRing>();
        services.TryAddSingleton<LocalTokenKeys>();

        // The ring silently drops a bad entry, so a resource server without password login needs its
        // own check or it starts clean and answers 401. It stands down when PasswordLoginStartupCheck is present.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, LocalSigningKeyStartupCheck>(provider =>
            new LocalSigningKeyStartupCheck(services, provider.GetRequiredService<LocalSigningKeyRing>())));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, AudienceStartupWarning>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PublishedSecretsStartupCheck>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Toamaisutaa.OpenIdConnect.PublishedSecretsLoopbackCheck>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Microsoft.AspNetCore.Hosting.IStartupFilter, Toamaisutaa.OpenIdConnect.PublishedSecretsProxyGuard>());

        // Here rather than in Core, which carries no JWT library.
        services.TryAddSingleton<IAccessTokenIssuer, LocalAccessTokenIssuer>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, ConfigureToamaisutaaJwtBearerOptions>());

        return services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
    }
}
