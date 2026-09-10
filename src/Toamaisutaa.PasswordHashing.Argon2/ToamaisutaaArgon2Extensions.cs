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
    /// Hashes passwords with Argon2id instead of the in-box PBKDF2. Optional - local login works
    /// without it, and this is the memory-hard upgrade for a deployment willing to carry the
    /// dependency that makes it possible.
    /// </summary>
    /// <remarks>
    /// Call it before <c>AddToamaisutaaPasswordLogin</c> or after; either way this wins, because a
    /// package installed for the hash and then quietly outvoted by registration order would be the
    /// worst possible outcome. Rows a deployment already has keep verifying and rewrite themselves
    /// as Argon2id on next sign-in, so there is nothing to migrate.
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

    /// <summary>Same thing from code. With no <paramref name="configure"/> the OWASP defaults
    /// stand, which is the configuration this package exists to hand out.</summary>
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
        // The salt length, the output length and the pepper are local-login settings, shared with
        // the hasher this one falls back to.
        services.AddOptions<ToamaisutaaLocalLoginOptions>();

        // Registered as itself, not as the IPasswordHasher: it is what reads the rows written
        // before this package arrived, and what writes them again if VerifyOnly is ever set.
        services.TryAddSingleton<Pbkdf2PasswordHasher>();

        // Replace rather than TryAdd, so registration order does not decide how passwords are
        // hashed. AddToamaisutaaPasswordLogin adds the PBKDF2 hasher with TryAdd, and whichever of
        // the two calls comes second would otherwise silently lose.
        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher, Argon2idPasswordHasher>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Argon2HashingStartupCheck>(provider =>
            new Argon2HashingStartupCheck(
                services,
                provider.GetRequiredService<IOptions<ToamaisutaaArgon2Options>>(),
                provider.GetRequiredService<ILogger<Argon2HashingStartupCheck>>())));

        return services;
    }
}
