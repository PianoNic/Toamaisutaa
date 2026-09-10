using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordHashing.Argon2;

/// <summary>
/// Refuses to start rather than hashing a real password with parameters that were never strong
/// enough, the same reasoning <c>PasswordLoginStartupCheck</c> uses for local login.
/// </summary>
/// <remarks>
/// Weak parameters are worse than a missing dependency here, because nothing about them is visible
/// afterwards: sign-in works, the rows look right, and the only symptom is how fast somebody else
/// cracks them. They also cannot be repaired in place - every password hashed under them stays that
/// way until its owner next signs in.
/// </remarks>
internal sealed class Argon2HashingStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaArgon2Options> options,
    ILogger<Argon2HashingStartupCheck> logger) : IHostedService
{
    /// <summary>
    /// The configurations OWASP publishes as equivalent, weakest memory first. Any one of them, or
    /// anything stronger than one of them, passes; the point of the table is that trading memory
    /// for passes is allowed and going below all five is not.
    /// </summary>
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
        {
            throw new InvalidOperationException(
                "Toamaisutaa Argon2 password hashing is registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// The failure this catches is silent: another <see cref="IPasswordHasher"/> registered after
    /// this package leaves it installed, configured, and hashing nothing.
    /// </summary>
    private void CheckRegistration(List<string> problems)
    {
        // The last registration is the one a single-service resolve gets.
        var hasher = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IPasswordHasher));

        var implementation = hasher?.ImplementationType ?? hasher?.ImplementationInstance?.GetType();

        // Null means a factory registration, whose type nothing can read here. Say nothing rather
        // than accuse it.
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

        if (settings.Iterations < 1)
        {
            problems.Add($"PasswordHashing:Argon2:Iterations is {settings.Iterations}; it has to be at least 1.");
            return;
        }

        if (settings.MemorySizeKib < 8 * settings.DegreeOfParallelism)
        {
            problems.Add(
                $"PasswordHashing:Argon2:MemorySizeKib is {settings.MemorySizeKib}, which is below the eight blocks per "
                + $"lane Argon2 needs for DegreeOfParallelism {settings.DegreeOfParallelism}.");
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
