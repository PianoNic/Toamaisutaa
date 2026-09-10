using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The hashing parameters, from both ends. The floors are about strength; the ceilings are about
/// whether the row can be read back at all, and only the second kind produces a wrong-password
/// answer to the correct password.
/// </summary>
/// <remarks>
/// The check reports every problem it finds at once, and a service collection with no stores in it
/// has plenty, so these assert on the parameter message rather than on the exception being thrown.
/// </remarks>
public class PasswordLoginStartupCheckTests
{
    private static string Run(Action<ToamaisutaaLocalLoginOptions> configure)
    {
        var settings = new ToamaisutaaLocalLoginOptions();
        configure(settings);

        var options = Options.Create(settings);
        var hasher = new Pbkdf2PasswordHasher(options);

        var check = new PasswordLoginStartupCheck(
            new ServiceCollection(),
            options,
            Options.Create(new ToamaisutaaOidcOptions()),
            new DummyPasswordHash(hasher),
            new LocalSigningKeyRing(options));

        try
        {
            check.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
            return string.Empty;
        }
        catch (InvalidOperationException exception)
        {
            return exception.Message;
        }
    }

    /// <summary>
    /// The hasher refuses a stored row longer than this, so a larger setting writes credentials the
    /// same process cannot verify - and the only symptom is a failed sign-in against the correct
    /// password.
    /// </summary>
    [Test]
    public async Task RefusesAHashSizeAboveWhatAStoredRowMayCarry()
    {
        var problems = Run(settings => settings.HashSizeBytes = 2_048);

        await Assert.That(problems).Contains("LocalLogin:HashSizeBytes is 2048");
        await Assert.That(problems).Contains("would fail to verify");
    }

    [Test]
    public async Task RefusesAnIterationCountAboveWhatAStoredRowMayName()
    {
        var problems = Run(settings => settings.Pbkdf2Iterations = 50_000_001);

        await Assert.That(problems).Contains("LocalLogin:Pbkdf2Iterations is 50000001");
        await Assert.That(problems).Contains("would fail to verify");
    }

    /// <summary>The bound itself is legal: refusing it would be refusing a row the hasher
    /// reads.</summary>
    [Test]
    public async Task AcceptsTheHighestHashSizeAStoredRowMayCarry()
    {
        var settings = new ToamaisutaaLocalLoginOptions { HashSizeBytes = 1_024 };
        var hasher = new Pbkdf2PasswordHasher(Options.Create(settings));

        await Assert.That(Run(configured => configured.HashSizeBytes = 1_024)).DoesNotContain("HashSizeBytes");
        await Assert.That(hasher.Verify("correct horse battery staple", hasher.Hash("correct horse battery staple")))
            .IsEqualTo(PasswordVerificationResult.Succeeded);
    }
}
