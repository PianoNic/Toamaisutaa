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
    /// Needs a store registration and <c>TwoFactor:EncryptionKey</c>, both checked at startup. It
    /// also needs somewhere for the second factor to actually apply, which means either
    /// <c>AddToamaisutaaPasswordLogin</c> or <c>AddToamaisutaaTwoFactorClaims</c> - registering
    /// neither leaves a feature that can be enrolled in and never enforced.
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
    /// Opt-in and off by default because it costs a database read on every authenticated request.
    /// It never adds <c>amr</c>: being enrolled is not having presented a second factor, and the
    /// provider owns that sign-in, so Toamaisutaa cannot say what was proved there. A policy that
    /// needs <c>amr=mfa</c> from a provider's user needs the provider to assert it, or a local
    /// step-up.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaTwoFactorClaims(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();

        // AddAuthentication registers a do-nothing transformation, and AddToamaisutaaBearer - which
        // has to come first - calls it. A plain TryAdd therefore never registered this at all, and
        // the transformation silently never ran. Only the framework's placeholder is replaced: an
        // application's own transformation still wins, as it did.
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

        // Registered here as well as by password login, because the enrolment endpoints verify
        // second factors whether or not this deployment has local sign-in.
        services.TryAddSingleton<ToamaisutaaMetrics>();

        services.TryAddScoped<TwoFactorVerifier>();
        services.TryAddScoped<TwoFactorGate>();

        // Registered here too: enabling or disabling a second factor takes the trusted devices with
        // it, and the gate answers harmlessly when no device store exists.
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

        return services;
    }
}

/// <summary>
/// Registers the policy named by <c>TwoFactor:EnrolledPolicyName</c>, which requires <c>amr</c> to
/// contain <c>mfa</c> - the RFC 8176 value for "a second factor was actually presented".
/// </summary>
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
