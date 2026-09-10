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
    /// call, and the length rules when nothing does yet. The wrapped registration keeps the lifetime
    /// it was made with, so a scoped validator of your own stays scoped.
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
        // Keyed registrations are somebody else's business: only the one everybody resolves is wrapped.
        var existing = services.LastOrDefault(descriptor =>
            descriptor.ServiceType == typeof(IPasswordValidator) && descriptor.ServiceKey is null);

        if (existing is not null)
            services.Remove(existing);

        // A key of its own per call, so wrapping a wrapper resolves the one below it rather than
        // itself.
        var innerKey = new object();
        var inner = InnerDescriptor(existing, innerKey);

        services.Add(inner);

        // The wrapped validator goes back into the container rather than being built by hand: it
        // keeps the lifetime it was registered with, is handed the provider of whatever scope asked
        // for it, and is disposed with that scope. Building it from this factory's provider would
        // resolve a scoped dependency from the root and dispose nothing.
        services.Add(new ServiceDescriptor(
            typeof(IPasswordValidator),
            provider => new HibpPasswordValidator(
                provider.GetRequiredKeyedService<IPasswordValidator>(innerKey),
                provider.GetRequiredService<IBreachedPasswordIndex>(),
                provider.GetRequiredService<Options.IOptions<ToamaisutaaHibpOptions>>(),
                provider.GetRequiredService<Logging.ILogger<HibpPasswordValidator>>()),
            inner.Lifetime));

        return services;
    }

    /// <summary>Puts the descriptor the breach check took out back under a private key, unchanged in
    /// everything but the key, so the container goes on building it the way it was asked to.</summary>
    private static ServiceDescriptor InnerDescriptor(ServiceDescriptor? descriptor, object key) => descriptor switch
    {
        null => new ServiceDescriptor(typeof(IPasswordValidator), key, typeof(DefaultPasswordValidator), ServiceLifetime.Singleton),
        { ImplementationInstance: IPasswordValidator instance } => new ServiceDescriptor(typeof(IPasswordValidator), key, instance),
        { ImplementationFactory: { } factory } => new ServiceDescriptor(typeof(IPasswordValidator), key, (provider, _) => factory(provider), descriptor.Lifetime),
        { ImplementationType: { } type } => new ServiceDescriptor(typeof(IPasswordValidator), key, type, descriptor.Lifetime),
        _ => throw new InvalidOperationException(
            "The registered IPasswordValidator has no implementation type, factory or instance, so the breach check has nothing to wrap."),
    };
}
