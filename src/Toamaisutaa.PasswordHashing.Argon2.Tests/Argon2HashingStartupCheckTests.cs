using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

public class Argon2HashingStartupCheckTests
{
    private static async Task<string?> RunAsync(Action<ToamaisutaaArgon2Options>? configure = null, Action<IServiceCollection>? register = null)
    {
        var services = new ServiceCollection();
        services.AddToamaisutaaArgon2PasswordHashing(configure);
        register?.Invoke(services);

        var options = new ToamaisutaaArgon2Options();
        configure?.Invoke(options);

        var check = new Argon2HashingStartupCheck(services, Options.Create(options), NullLogger<Argon2HashingStartupCheck>.Instance);

        try
        {
            await check.StartAsync(CancellationToken.None);
            return null;
        }
        catch (InvalidOperationException exception)
        {
            return exception.Message;
        }
    }

    [Test]
    public async Task AcceptsTheDefaults()
    {
        await Assert.That(await RunAsync()).IsNull();
    }

    /// <summary>OWASP publishes five configurations as equivalent, so the check cannot be a single
    /// floor on memory: 46 MiB with one pass is one of them.</summary>
    [Test]
    [Arguments(47_104, 1)]
    [Arguments(19_456, 2)]
    [Arguments(12_288, 3)]
    [Arguments(9_216, 4)]
    [Arguments(7_168, 5)]
    [Arguments(65_536, 3)]
    public async Task AcceptsEveryOwaspConfiguration(int memory, int iterations)
    {
        var problems = await RunAsync(options =>
        {
            options.MemorySizeKib = memory;
            options.Iterations = iterations;
        });

        await Assert.That(problems).IsNull();
    }

    [Test]
    [Arguments(19_456, 1)]
    [Arguments(7_167, 5)]
    [Arguments(1_024, 2)]
    public async Task RefusesParametersWeakerThanEveryOwaspConfiguration(int memory, int iterations)
    {
        var problems = await RunAsync(options =>
        {
            options.MemorySizeKib = memory;
            options.Iterations = iterations;
        });

        await Assert.That(problems).Contains("weaker than every OWASP configuration");
    }

    [Test]
    public async Task RefusesFewerThanEightBlocksPerLane()
    {
        var problems = await RunAsync(options =>
        {
            options.MemorySizeKib = 4;
            options.DegreeOfParallelism = 1;
        });

        await Assert.That(problems).Contains("eight blocks per lane");
    }

    [Test]
    public async Task RefusesNoLanes()
    {
        await Assert.That(await RunAsync(options => options.DegreeOfParallelism = 0)).Contains("DegreeOfParallelism");
    }

    /// <summary>
    /// The silent failure: the package is installed, configured and hashing nothing because
    /// something else was registered after it.
    /// </summary>
    [Test]
    public async Task RefusesWhenAnotherHasherIsRegisteredAfterIt()
    {
        var problems = await RunAsync(register: services => services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>());

        await Assert.That(problems).Contains("Pbkdf2PasswordHasher");
    }

    /// <summary>Weak parameters do not matter while nothing is hashed with them, and a startup
    /// failure over an unused setting is a startup failure nobody can act on.</summary>
    [Test]
    public async Task VerifyOnlyIgnoresTheParameters()
    {
        var problems = await RunAsync(options =>
        {
            options.VerifyOnly = true;
            options.MemorySizeKib = 8;
            options.Iterations = 1;
        });

        await Assert.That(problems).IsNull();
    }
}
