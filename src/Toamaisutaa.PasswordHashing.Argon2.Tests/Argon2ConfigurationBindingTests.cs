using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

/// <summary>
/// Asserts off the hashed row rather than the options object, because a bind that reaches nothing
/// still starts and hashes Argon2id with the defaults.
/// </summary>
public class Argon2ConfigurationBindingTests
{
    private const string Password = "correct horse battery staple";

    // Not the default, so a row carrying it could not have come from an unbound options object.
    private const int NonDefaultMemoryKib = 47_104;

    [Test]
    public async Task ParametersInTheDocumentedSectionReachTheHasher()
    {
        var hash = Hash(new Dictionary<string, string?>
        {
            ["PasswordHashing:Argon2:MemorySizeKib"] = NonDefaultMemoryKib.ToString(),
            ["PasswordHashing:Argon2:Iterations"] = "1",
        });

        await Assert.That(hash).StartsWith($"$argon2id$v=19$m={NonDefaultMemoryKib},t=1,p=1$");
    }

    [Test]
    public async Task VerifyOnlyInConfigurationReachesTheHasher()
    {
        var hash = Hash(new Dictionary<string, string?> { ["PasswordHashing:Argon2:VerifyOnly"] = "true" });

        await Assert.That(hash).StartsWith("$pbkdf2-sha256$");
    }

    [Test]
    public async Task ReadsTheSectionItWasGiven()
    {
        var hash = Hash(
            new Dictionary<string, string?>
            {
                ["Hashing:Argon2:MemorySizeKib"] = NonDefaultMemoryKib.ToString(),
                ["Hashing:Argon2:Iterations"] = "1",
            },
            "Hashing:Argon2");

        await Assert.That(hash).StartsWith($"$argon2id$v=19$m={NonDefaultMemoryKib},t=1,p=1$");
    }

    private static string Hash(Dictionary<string, string?> settings, string? sectionName = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();

        if (sectionName is null)
            services.AddToamaisutaaArgon2PasswordHashing(configuration);
        else
            services.AddToamaisutaaArgon2PasswordHashing(configuration, sectionName);

        return services.BuildServiceProvider().GetRequiredService<IPasswordHasher>().Hash(Password);
    }
}
