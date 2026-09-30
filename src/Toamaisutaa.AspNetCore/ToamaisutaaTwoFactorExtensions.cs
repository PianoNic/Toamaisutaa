using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Core;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaTwoFactorExtensions
{
    /// <summary>
    /// Adds TOTP two-factor authentication: enrolment, recovery codes, and the challenge step that
    /// a local sign-in stops at once a user is enrolled.
    /// </summary>
    /// <remarks>
    /// Needs a store registration and <c>TwoFactor:EncryptionKey</c>, both checked at startup, and
    /// either <c>AddToamaisutaaPasswordLogin</c> or <c>AddToamaisutaaTwoFactorClaims</c>, without which
    /// enrolment is possible but never enforced.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaTwoFactor(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaDefaults.TwoFactorConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaTwoFactorOptions>().Bind(configuration.GetSection(sectionName));

        return AddTwoFactorCore(services);
    }

    public static IServiceCollection AddToamaisutaaTwoFactor(
        this IServiceCollection services,
        Action<ToamaisutaaTwoFactorOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.Configure(configure);

        return AddTwoFactorCore(services);
    }

    /// <summary>
    /// Tells a policy about the local enrolment of users who sign in through an identity provider,
    /// by adding <c>toa_2fa_enrolled</c> - or <c>toa_2fa_required</c>, under <c>RequiredForAll</c>,
    /// when they have not enrolled - to the token the provider issued.
    /// </summary>
    /// <remarks>
    /// Costs a database read on every authenticated request. It never adds <c>amr</c>, because being
    /// enrolled is not having presented a second factor; <c>amr=mfa</c> for a provider's user needs the
    /// provider to assert it, or a local step-up.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaTwoFactorClaims(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // AddAuthentication registers a no-op transformation that would make TryAdd skip this; only that
        // placeholder is replaced, so an application's own transformation still wins.
        var placeholder = services.FirstOrDefault(descriptor =>
            descriptor.ServiceType == typeof(IClaimsTransformation)
            && descriptor.ImplementationType == typeof(NoopClaimsTransformation));

        if (placeholder is not null)
            services.Remove(placeholder);

        services.TryAddScoped<IClaimsTransformation, TwoFactorClaimsTransformation>();

        return services;
    }

    private static IServiceCollection AddTwoFactorCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<ITotpProvider, TotpProvider>();
        services.TryAddSingleton<IRecoveryCodeProvider, RecoveryCodeProvider>();
        services.TryAddSingleton<ISecretProtector, AesGcmSecretProtector>();

        services.TryAddSingleton<ToamaisutaaMetrics>();

        services.TryAddScoped<TwoFactorVerifier>();
        services.TryAddScoped<TwoFactorGate>();

        // Enabling or disabling a second factor revokes trusted devices, so the gate is needed even without them.
        services.AddOptions<ToamaisutaaTrustedDeviceOptions>();
        services.TryAddScoped<TrustedDeviceGate>();
        services.TryAddScoped<AuthenticationEventPublisher>();
        services.TryAddScoped<ITwoFactorService, TwoFactorService>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<AuthorizationOptions>, ConfigureToamaisutaaTwoFactorPolicy>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TwoFactorStartupCheck>(provider =>
            new TwoFactorStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaTwoFactorOptions>>())));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PublishedSecretsStartupCheck>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Toamaisutaa.OpenIdConnect.PublishedSecretsLoopbackCheck>());

        return services;
    }
}

internal sealed class ConfigureToamaisutaaTwoFactorPolicy(IOptions<ToamaisutaaTwoFactorOptions> options)
    : IConfigureOptions<AuthorizationOptions>
{
    public void Configure(AuthorizationOptions authorization)
    {
        var name = options.Value.EnrolledPolicyName;

        if (string.IsNullOrWhiteSpace(name))
            return;

        authorization.AddPolicy(
            name,
            policy => policy
                .RequireAuthenticatedUser()
                .RequireClaim(ToamaisutaaDefaults.AuthenticationMethodClaim, ToamaisutaaDefaults.MultiFactorMethod));
    }
}
