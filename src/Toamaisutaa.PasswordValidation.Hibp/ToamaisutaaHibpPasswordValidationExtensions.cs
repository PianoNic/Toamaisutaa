using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.PasswordValidation.Hibp;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaHibpPasswordValidationExtensions
{
    /// <summary>
    /// Adds a Have I Been Pwned breach check on top of the password rules already in place. Optional
    /// - local password login works without it, and the length floor is unchanged either way.
    /// </summary>
    /// <remarks>
    /// Order against <c>AddToamaisutaaPasswordLogin</c> does not matter, only that both run. What
    /// the check wraps is whatever <see cref="IPasswordValidator"/> stands at the moment of this
    /// call, and the length rules when nothing does yet.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaHibpPasswordValidation(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ToamaisutaaHibpDefaults.ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaHibpOptions>().Bind(configuration.GetSection(sectionName));

        return AddHibpCore(services);
    }

    public static IServiceCollection AddToamaisutaaHibpPasswordValidation(
        this IServiceCollection services,
        Action<ToamaisutaaHibpOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaHibpOptions>();
        services.Configure(configure);

        return AddHibpCore(services);
    }

    private static IServiceCollection AddHibpCore(IServiceCollection services)
    {
        services.AddHttpClient(ToamaisutaaHibpDefaults.HttpClientName);

        services.TryAddSingleton<IBreachedPasswordIndex, PwnedPasswordsRangeIndex>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, HibpStartupCheck>());

        // Composed, not substituted: whatever validator stands here becomes the one the check runs
        // after. Registering over it rather than beside it is what keeps the length rules from
        // being answered twice, and taking the old descriptor out is what keeps the container from
        // handing somebody the unwrapped one.
        //
        // Either order works. Called after AddToamaisutaaPasswordLogin this finds the length rules;
        // called before, it finds nothing and builds them itself, and the TryAdd inside
        // AddToamaisutaaPasswordLogin then leaves this registration alone.
        var existing = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IPasswordValidator));

        if (existing is not null)
            services.Remove(existing);

        services.AddSingleton<IPasswordValidator>(provider => new HibpPasswordValidator(
            ResolveInner(provider, existing),
            provider.GetRequiredService<IBreachedPasswordIndex>(),
            provider.GetRequiredService<Options.IOptions<ToamaisutaaHibpOptions>>(),
            provider.GetRequiredService<Logging.ILogger<HibpPasswordValidator>>()));

        return services;
    }

    /// <summary>Builds the validator a descriptor described, now that the descriptor itself is no
    /// longer in the container to do it.</summary>
    private static IPasswordValidator ResolveInner(IServiceProvider provider, ServiceDescriptor? descriptor) => descriptor switch
    {
        null => ActivatorUtilities.CreateInstance<DefaultPasswordValidator>(provider),
        { ImplementationInstance: IPasswordValidator instance } => instance,
        { ImplementationFactory: { } factory } => (IPasswordValidator)factory(provider),
        { ImplementationType: { } type } => (IPasswordValidator)ActivatorUtilities.CreateInstance(provider, type),
        _ => throw new InvalidOperationException(
            "The registered IPasswordValidator has no implementation type, factory or instance, so the breach check has nothing to wrap."),
    };
}
