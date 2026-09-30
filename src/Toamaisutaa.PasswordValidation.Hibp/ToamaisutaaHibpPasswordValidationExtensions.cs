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
    /// Adds a Have I Been Pwned breach check on top of the password rules already in place.
    /// </summary>
    /// <remarks>
    /// Order against <c>AddToamaisutaaPasswordLogin</c> does not matter. The check wraps whatever
    /// <see cref="IPasswordValidator"/> is registered at the moment of this call, keeping its
    /// lifetime, or the length rules when nothing is yet.
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

        // The old descriptor is removed so the container never hands out the unwrapped validator.
        // Called before AddToamaisutaaPasswordLogin, its TryAdd then leaves this registration alone.
        var existing = services.LastOrDefault(descriptor =>
            descriptor.ServiceType == typeof(IPasswordValidator) && descriptor.ServiceKey is null);

        if (existing is not null)
            services.Remove(existing);

        // A key per call, so wrapping a wrapper resolves the one below it rather than itself.
        var innerKey = new object();
        var inner = InnerDescriptor(existing, innerKey);

        services.Add(inner);

        // Resolved from the container rather than built by hand, which would resolve a scoped
        // dependency from the root and dispose nothing.
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
