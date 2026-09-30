using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

/// <summary>
/// The TryAdd registrations stand in for <c>AddToamaisutaaPasswordLogin</c>, which adds the PBKDF2
/// hasher that way.
/// </summary>
public class ToamaisutaaArgon2ExtensionsTests
{
    [Test]
    public async Task WinsWhenTheDefaultHasherWasRegisteredFirst()
    {
        var services = new ServiceCollection();
        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddToamaisutaaArgon2PasswordHashing();

        await Assert.That(Resolve(services)).IsTypeOf<Argon2idPasswordHasher>();
    }

    [Test]
    public async Task WinsWhenTheDefaultHasherIsRegisteredAfterwards()
    {
        var services = new ServiceCollection();
        services.AddToamaisutaaArgon2PasswordHashing();
        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();

        await Assert.That(Resolve(services)).IsTypeOf<Argon2idPasswordHasher>();
    }

    [Test]
    public async Task TheResolvedHasherWritesArgon2idRows()
    {
        var services = new ServiceCollection();
        services.AddToamaisutaaArgon2PasswordHashing();

        await Assert.That(Resolve(services).Hash("correct horse battery staple")).StartsWith("$argon2id$");
    }

    private static IPasswordHasher Resolve(IServiceCollection services) =>
        services.BuildServiceProvider().GetRequiredService<IPasswordHasher>();
}
