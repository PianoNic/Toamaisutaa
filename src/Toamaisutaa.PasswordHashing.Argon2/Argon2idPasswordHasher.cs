using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2;

/// <summary>
/// Argon2id in the canonical PHC format, <c>$argon2id$v=19$m=19456,t=2,p=1$salt$hash</c>, with the
/// PBKDF2 hasher underneath it for every row this package did not write.
/// </summary>
/// <remarks>
/// Existing PBKDF2 rows verify through <see cref="Pbkdf2PasswordHasher"/> and a correct password
/// is answered with <see cref="PasswordVerificationResult.SucceededRehashNeeded"/>, so they migrate
/// to Argon2id on sign-in. <see cref="ToamaisutaaArgon2Options.VerifyOnly"/> runs the migration
/// backwards.
/// </remarks>
public sealed class Argon2idPasswordHasher(
    IOptions<ToamaisutaaArgon2Options> options,
    IOptions<ToamaisutaaLocalLoginOptions> loginOptions,
    Pbkdf2PasswordHasher pbkdf2) : IPasswordHasher
{
    internal const string AlgorithmName = "argon2id";

    /// <summary>0x13, the only version implemented; a row naming another is refused rather than
    /// guessed at.</summary>
    private const int Argon2Version = 19;

    private const string MemoryParameter = "m";
    private const string IterationsParameter = "t";
    private const string ParallelismParameter = "p";

    private const string PepperVersionParameter = "keyid";

    // A database an attacker can write could otherwise make each login attempt demand a gigabyte
    // and a minute of work. Argon2HashingStartupCheck refuses configured values above these, since
    // rows written with them would never verify.
    internal const int MaxMemoryKib = 1024 * 1024;
    internal const int MaxIterations = 64;
    internal const int MaxParallelism = 64;
    private const int MaxHashSizeBytes = 1024;

    // RFC 9106 floors. Konscious computes a shorter salt or tag without complaint, so nothing but
    // this refuses a row that no compliant implementation could have written.
    private const int MinSaltSizeBytes = 8;
    private const int MinHashSizeBytes = 4;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (options.Value.VerifyOnly)
            return pbkdf2.Hash(password);

        var settings = loginOptions.Value;
        var argon = options.Value;
        var pepper = PasswordPepper.Active(settings);

        var salt = RandomNumberGenerator.GetBytes(settings.SaltSizeBytes);
        var hash = Derive(
            PasswordPepper.Preprocess(password, pepper),
            salt,
            argon.MemorySizeKib,
            argon.Iterations,
            argon.DegreeOfParallelism,
            settings.HashSizeBytes);

        var parameters = new List<KeyValuePair<string, string>>
        {
            new(MemoryParameter, argon.MemorySizeKib.ToString()),
            new(IterationsParameter, argon.Iterations.ToString()),
            new(ParallelismParameter, argon.DegreeOfParallelism.ToString()),
        };

        if (PasswordPepper.ActiveVersion(settings) is { } pepperVersion)
            parameters.Add(new KeyValuePair<string, string>(PepperVersionParameter, pepperVersion));

        return PhcString.Format(AlgorithmName, Argon2Version, parameters, salt, hash);
    }

    public PasswordVerificationResult Verify(string password, string hash)
    {
        if (password is null || !PhcString.TryParse(hash, out var stored))
            return PasswordVerificationResult.Failed;

        if (!string.Equals(stored.Algorithm, AlgorithmName, StringComparison.Ordinal))
            return VerifyThroughPbkdf2(password, hash);

        if (stored.Version != Argon2Version)
            return PasswordVerificationResult.Failed;

        if (!TryReadParameters(stored, out var memory, out var iterations, out var parallelism))
            return PasswordVerificationResult.Failed;

        if (stored.Salt.Length < MinSaltSizeBytes
            || stored.Hash.Length < MinHashSizeBytes
            || stored.Hash.Length > MaxHashSizeBytes)
        {
            return PasswordVerificationResult.Failed;
        }

        if (!TryReadPepperVersion(stored, out var pepperVersion))
            return PasswordVerificationResult.Failed;

        // A row peppered with a key this deployment no longer holds cannot be checked, so fail closed.
        if (!PasswordPepper.TryResolve(loginOptions.Value, pepperVersion, out var pepper))
            return PasswordVerificationResult.Failed;

        var computed = Derive(
            PasswordPepper.Preprocess(password, pepper),
            stored.Salt,
            memory,
            iterations,
            parallelism,
            stored.Hash.Length);

        if (!CryptographicOperations.FixedTimeEquals(computed, stored.Hash))
            return PasswordVerificationResult.Failed;

        // VerifyOnly drains these rows back to PBKDF2.
        if (options.Value.VerifyOnly)
            return PasswordVerificationResult.SucceededRehashNeeded;

        return NeedsRehash(stored, memory, iterations, parallelism, pepperVersion)
            ? PasswordVerificationResult.SucceededRehashNeeded
            : PasswordVerificationResult.Succeeded;
    }

    private PasswordVerificationResult VerifyThroughPbkdf2(string password, string hash)
    {
        var result = pbkdf2.Verify(password, hash);

        return result == PasswordVerificationResult.Succeeded && !options.Value.VerifyOnly
            ? PasswordVerificationResult.SucceededRehashNeeded
            : result;
    }

    private static bool TryReadParameters(PhcString stored, out int memory, out int iterations, out int parallelism)
    {
        memory = 0;
        iterations = 0;

        if (!stored.TryGetInt32(ParallelismParameter, out parallelism) || parallelism is < 1 or > MaxParallelism)
            return false;

        if (!stored.TryGetInt32(IterationsParameter, out iterations) || iterations is < 1 or > MaxIterations)
            return false;

        // Argon2 needs eight blocks per lane; below that there is no valid row to check against.
        return stored.TryGetInt32(MemoryParameter, out memory)
            && memory >= 8 * parallelism
            && memory <= MaxMemoryKib;
    }

    private static bool TryReadPepperVersion(PhcString stored, out string? version)
    {
        version = null;

        if (!stored.Parameters.TryGetValue(PepperVersionParameter, out var raw))
            return true;

        if (raw.Length == 0 || !raw.All(char.IsLetterOrDigit))
            return false;

        version = raw;
        return true;
    }

    private bool NeedsRehash(PhcString stored, int memory, int iterations, int parallelism, string? pepperVersion)
    {
        var settings = loginOptions.Value;
        var argon = options.Value;

        return memory < argon.MemorySizeKib
            || iterations < argon.Iterations
            // Lanes divide the memory rather than add to it, so any mismatch is rewritten, not ranked.
            || parallelism != argon.DegreeOfParallelism
            || stored.Salt.Length < settings.SaltSizeBytes
            || stored.Hash.Length < settings.HashSizeBytes
            || !string.Equals(pepperVersion, PasswordPepper.ActiveVersion(settings), StringComparison.Ordinal);
    }

    private static byte[] Derive(byte[] secret, byte[] salt, int memoryKib, int iterations, int parallelism, int length)
    {
        using var argon2 = new Argon2id(secret)
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };

        return argon2.GetBytes(length);
    }
}
