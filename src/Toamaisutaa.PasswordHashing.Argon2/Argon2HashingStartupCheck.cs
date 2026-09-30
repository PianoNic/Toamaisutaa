using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2;

/// <summary>
/// Refuses to start on parameters too weak to protect a password or above the bounds the hasher
/// reads back, since either failure is invisible once rows have been written with them.
/// </summary>
internal sealed class Argon2HashingStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaArgon2Options> options,
    ILogger<Argon2HashingStartupCheck> logger) : IHostedService
{
    /// <summary>The configurations OWASP publishes as equivalent; meeting any one of them passes.</summary>
    private static readonly (int MemoryKib, int Iterations)[] OwaspConfigurations =
    [
        (47_104, 1),
        (19_456, 2),
        (12_288, 3),
        (9_216, 4),
        (7_168, 5),
    ];

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        CheckRegistration(problems);

        if (settings.VerifyOnly)
        {
            logger.LogWarning(
                "PasswordHashing:Argon2:VerifyOnly is on. New passwords are hashed with PBKDF2, and every Argon2id row "
                + "is rewritten as PBKDF2 the next time its owner signs in.");
        }
        else
        {
            CheckParameters(settings, problems);
        }

        if (problems.Count > 0)
            throw StartupProblems.Refusal("Toamaisutaa Argon2 password hashing is registered but not usable:", problems);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Another <see cref="IPasswordHasher"/> registered after this package silently leaves it
    /// hashing nothing.
    /// </summary>
    private void CheckRegistration(List<string> problems)
    {
        var hasher = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IPasswordHasher));

        var implementation = hasher?.ImplementationType ?? hasher?.ImplementationInstance?.GetType();

        // Null means a factory registration, whose type cannot be read here, so it is not accused.
        if (implementation is null || implementation == typeof(Argon2idPasswordHasher))
            return;

        problems.Add(
            $"{implementation.Name} is registered as the IPasswordHasher after this package, so passwords are not "
            + "hashed with Argon2id. Register it before AddToamaisutaaArgon2PasswordHashing, or drop one of the two.");
    }

    private static void CheckParameters(ToamaisutaaArgon2Options settings, List<string> problems)
    {
        if (settings.DegreeOfParallelism < 1)
        {
            problems.Add($"PasswordHashing:Argon2:DegreeOfParallelism is {settings.DegreeOfParallelism}; it has to be at least 1.");
            return;
        }

        if (settings.DegreeOfParallelism > Argon2idPasswordHasher.MaxParallelism)
        {
            problems.Add(
                $"PasswordHashing:Argon2:DegreeOfParallelism is {settings.DegreeOfParallelism}; "
                + $"{Argon2idPasswordHasher.MaxParallelism} is the highest a stored row may name, so every row written "
                + "with it would fail to verify.");
            return;
        }

        if (settings.Iterations < 1)
        {
            problems.Add($"PasswordHashing:Argon2:Iterations is {settings.Iterations}; it has to be at least 1.");
            return;
        }

        if (settings.Iterations > Argon2idPasswordHasher.MaxIterations)
        {
            problems.Add(
                $"PasswordHashing:Argon2:Iterations is {settings.Iterations}; {Argon2idPasswordHasher.MaxIterations} is "
                + "the highest a stored row may name, so every row written with it would fail to verify.");
            return;
        }

        if (settings.MemorySizeKib < 8 * settings.DegreeOfParallelism)
        {
            problems.Add(
                $"PasswordHashing:Argon2:MemorySizeKib is {settings.MemorySizeKib}, which is below the eight blocks per "
                + $"lane Argon2 needs for DegreeOfParallelism {settings.DegreeOfParallelism}.");
            return;
        }

        if (settings.MemorySizeKib > Argon2idPasswordHasher.MaxMemoryKib)
        {
            problems.Add(
                $"PasswordHashing:Argon2:MemorySizeKib is {settings.MemorySizeKib}; "
                + $"{Argon2idPasswordHasher.MaxMemoryKib} is the highest a stored row may name, so every row written "
                + "with it would fail to verify.");
            return;
        }

        var meetsOwasp = OwaspConfigurations.Any(configuration =>
            settings.MemorySizeKib >= configuration.MemoryKib && settings.Iterations >= configuration.Iterations);

        if (!meetsOwasp)
        {
            problems.Add(
                $"PasswordHashing:Argon2 is m={settings.MemorySizeKib},t={settings.Iterations}, which is weaker than every "
                + "OWASP configuration. Use m=47104,t=1 or m=19456,t=2 or m=12288,t=3 or m=9216,t=4 or m=7168,t=5, or "
                + "anything above one of them.");
        }
    }
}
