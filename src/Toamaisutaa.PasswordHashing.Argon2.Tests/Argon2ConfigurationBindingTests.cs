using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

/// <summary>
/// The <see cref="IConfiguration"/> overload, which is the one the README, the docs and the sample
/// all show and the only one that reads anything out of a configuration section.
/// </summary>
/// <remarks>
/// A bind that reaches nothing is invisible from outside: the defaults are the OWASP baseline, the
/// startup check only refuses parameters weaker than them, and the host starts and hashes Argon2id
/// either way. So these tests assert off the row the resolved hasher produces rather than off the
/// options object, because the row is the only place a configured value shows up.
/// </remarks>
public class Argon2ConfigurationBindingTests
{
    private const string Password = "correct horse battery staple";

    // One pass over 46 MiB: an OWASP configuration, and not the default one, so a row carrying it
    // could not have come from an unbound options object.
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

    /// <summary>
    /// The setting a deployment leaving this package depends on. Nothing else reports whether it
    /// took: with it ignored the rows stay Argon2id, the drain never happens, and the package is
    /// uninstalled out from under rows nothing can read.
    /// </summary>
    [Test]
    public async Task VerifyOnlyInConfigurationReachesTheHasher()
    {
        var hash = Hash(new Dictionary<string, string?> { ["PasswordHashing:Argon2:VerifyOnly"] = "true" });

        await Assert.That(hash).StartsWith("$pbkdf2-sha256$");
    }

    /// <summary>The section name is a parameter, so a deployment that keeps its settings somewhere
    /// else is reading that somewhere else and not the default.</summary>
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
