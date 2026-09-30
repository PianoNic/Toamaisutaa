using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.PasswordHashing.Argon2;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaArgon2Extensions
{
    private const string ConfigurationSection = "PasswordHashing:Argon2";

    /// <summary>
    /// Hashes passwords with Argon2id instead of the in-box PBKDF2.
    /// </summary>
    /// <remarks>
    /// Wins over <c>AddToamaisutaaPasswordLogin</c> regardless of call order. Existing rows keep
    /// verifying and are rewritten as Argon2id on next sign-in, so there is nothing to migrate.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaArgon2PasswordHashing(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaArgon2Options>().Bind(configuration.GetSection(sectionName));

        return AddArgon2PasswordHashingCore(services);
    }

    /// <summary>Hashes passwords with Argon2id, configured from code. With no
    /// <paramref name="configure"/> the OWASP defaults stand.</summary>
    public static IServiceCollection AddToamaisutaaArgon2PasswordHashing(
        this IServiceCollection services,
        Action<ToamaisutaaArgon2Options>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ToamaisutaaArgon2Options>();

        if (configure is not null)
            services.Configure(configure);

        return AddArgon2PasswordHashingCore(services);
    }

    private static IServiceCollection AddArgon2PasswordHashingCore(IServiceCollection services)
    {
        services.AddOptions<ToamaisutaaLocalLoginOptions>();

        // Registered as itself, not as the IPasswordHasher: it reads pre-existing rows and writes
        // them again under VerifyOnly.
        services.TryAddSingleton<Pbkdf2PasswordHasher>();

        // Replace rather than TryAdd: AddToamaisutaaPasswordLogin uses TryAdd, so registration
        // order would otherwise silently decide how passwords are hashed.
        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher, Argon2idPasswordHasher>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Argon2HashingStartupCheck>(provider =>
            new Argon2HashingStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaArgon2Options>>(),
                provider.GetRequiredService<ILogger<Argon2HashingStartupCheck>>())));

        return services;
    }
}
