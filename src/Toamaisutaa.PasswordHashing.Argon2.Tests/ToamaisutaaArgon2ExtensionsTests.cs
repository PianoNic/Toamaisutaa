using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

/// <summary>
/// Registration order must not decide how passwords are hashed. <c>AddToamaisutaaPasswordLogin</c>
/// adds the PBKDF2 hasher with TryAdd, which is what these tests stand in for, and a package
/// installed for the hash that quietly loses a coin toss is the worst outcome available.
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

    /// <summary>The graph, not just the descriptor: the hasher needs the PBKDF2 one underneath it
    /// and both option types bound, and a missing registration is a startup crash.</summary>
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
