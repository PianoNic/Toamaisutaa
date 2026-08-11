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
    /// Makes the enrolment policy work for users who sign in through an identity provider, by
    /// looking up their local enrolment and adding <c>amr</c> to the token it issued.
    /// </summary>
    /// <remarks>
    /// Opt-in and off by default because it costs a database read on every authenticated request.
    /// It is also the only thing that can be done for those users: the identity provider owns that
    /// sign-in and Toamaisutaa never sees it, so this makes a policy enforceable rather than making
    /// the provider ask for a second factor.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaTwoFactorClaims(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaTwoFactorOptions>();
        services.AddOptions<ToamaisutaaProvisioningOptions>();
        services.TryAddScoped<IClaimsTransformation, TwoFactorClaimsTransformation>();

        return services;
    }

    private static IServiceCollection AddTwoFactorCore(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<ITotpProvider, TotpProvider>();
        services.TryAddSingleton<IRecoveryCodeProvider, RecoveryCodeProvider>();
        services.TryAddSingleton<ISecretProtector, AesGcmSecretProtector>();

        services.TryAddScoped<TwoFactorVerifier>();
        services.TryAddScoped<TwoFactorGate>();

        // Registered here too: enabling or disabling a second factor takes the trusted devices with
        // it, and the gate answers harmlessly when no device store exists.
        services.AddOptions<ToamaisutaaTrustedDeviceOptions>();
        services.TryAddScoped<TrustedDeviceGate>();
        services.TryAddScoped<ITwoFactorService, TwoFactorService>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<AuthorizationOptions>, ConfigureToamaisutaaTwoFactorPolicy>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TwoFactorStartupCheck>(provider =>
            new TwoFactorStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaTwoFactorOptions>>())));

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
