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
        // Userinfo claims live here, for the stampede protection: a cold start fires a dozen
        // requests carrying one token before any of them has answered. A registered
        // IDistributedCache is used as a second level only when Oidc:ShareUserInfoCacheAcrossInstances
        // says so, because these entries decide authorization.
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

        // The ring never throws on a bad entry - it collects one into Problems, and in a process
        // that registered password login PasswordLoginStartupCheck is what prints them. In the
        // resource server above, nothing did: the entry was dropped, the host started clean, and
        // every token it was meant to accept came back 401. This check stands down when the other
        // one is present, so the same line is never printed twice.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, LocalSigningKeyStartupCheck>(provider =>
            new LocalSigningKeyStartupCheck(services, provider.GetRequiredService<LocalSigningKeyRing>())));

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
