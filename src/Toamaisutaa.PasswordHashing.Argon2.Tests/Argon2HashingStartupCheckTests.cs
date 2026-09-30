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

    [Test]
    [Arguments(47_104, 65, 1, "Iterations is 65")]
    [Arguments(47_104, 2, 65, "DegreeOfParallelism is 65")]
    [Arguments(1_048_577, 2, 1, "MemorySizeKib is 1048577")]
    public async Task RefusesParametersTheHasherWouldNotReadBack(int memory, int iterations, int parallelism, string expected)
    {
        var problems = await RunAsync(options =>
        {
            options.MemorySizeKib = memory;
            options.Iterations = iterations;
            options.DegreeOfParallelism = parallelism;
        });

        await Assert.That(problems).Contains(expected);
        await Assert.That(problems).Contains("would fail to verify");
    }

    [Test]
    public async Task AcceptsTheHighestParametersTheHasherReadsBack()
    {
        var problems = await RunAsync(options =>
        {
            options.MemorySizeKib = 1_048_576;
            options.Iterations = 64;
            options.DegreeOfParallelism = 64;
        });

        await Assert.That(problems).IsNull();
    }

    /// <summary>Uses the smallest OWASP memory rather than the ceiling, because these derivations
    /// are real.</summary>
    [Test]
    [Arguments(7_168, 64, 1)]
    [Arguments(7_168, 5, 64)]
    [Arguments(47_104, 1, 1)]
    public async Task WhatItAcceptsRoundTripsThroughTheHasher(int memory, int iterations, int parallelism)
    {
        void Configure(ToamaisutaaArgon2Options options)
        {
            options.MemorySizeKib = memory;
            options.Iterations = iterations;
            options.DegreeOfParallelism = parallelism;
        }

        await Assert.That(await RunAsync(Configure)).IsNull();

        var argon = new ToamaisutaaArgon2Options();
        Configure(argon);

        var login = Options.Create(new ToamaisutaaLocalLoginOptions());
        var hasher = new Argon2idPasswordHasher(Options.Create(argon), login, new Pbkdf2PasswordHasher(login));

        const string password = "correct horse battery staple";

        await Assert.That(hasher.Verify(password, hasher.Hash(password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task RefusesWhenAnotherHasherIsRegisteredAfterIt()
    {
        var problems = await RunAsync(register: services => services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>());

        await Assert.That(problems).Contains("Pbkdf2PasswordHasher");
    }

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
