using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// PBKDF2-HMAC-SHA256, entirely from the base class library, with an optional pepper.
/// </summary>
/// <remarks>
/// <para>
/// PBKDF2 is compute-hard, not memory-hard, so it is materially weaker than Argon2id against an
/// attacker with GPUs. Install <c>Toamaisutaa.PasswordHashing.Argon2</c> or register your own
/// <see cref="IPasswordHasher"/>; existing rows migrate through
/// <see cref="PasswordVerificationResult.SucceededRehashNeeded"/>.
/// </para>
/// <para>
/// A configured pepper stores <c>PBKDF2(HMAC-SHA256(pepper, password), salt)</c> with the pepper
/// version in the algorithm name, so a pepper can be introduced or rotated without a migration.
/// </para>
/// </remarks>
public sealed class Pbkdf2PasswordHasher(IOptions<ToamaisutaaLocalLoginOptions> options) : IPasswordHasher
{
    internal const string AlgorithmName = "pbkdf2-sha256";
    internal const string PepperedAlgorithmPrefix = AlgorithmName + "-p";
    private const string IterationsParameter = "i";

    // Bounds what a stored row may request, so a writable database cannot make this process spend
    // minutes in a derivation. PasswordLoginStartupCheck refuses configured values above them, or
    // this hasher would write rows it cannot read back.
    internal const int MaxIterations = 50_000_000;
    internal const int MaxHashSizeBytes = 1024;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var settings = options.Value;
        var pepper = PasswordPepper.Active(settings);

        var salt = RandomNumberGenerator.GetBytes(settings.SaltSizeBytes);
        var secret = PasswordPepper.Preprocess(password, pepper);
        var hash = Derive(secret, salt, settings.Pbkdf2Iterations, settings.HashSizeBytes);

        var algorithm = pepper is null ? AlgorithmName : PepperedAlgorithmPrefix + settings.PepperVersion;

        return PhcString.Format(
            algorithm,
            [new KeyValuePair<string, string>(IterationsParameter, settings.Pbkdf2Iterations.ToString())],
            salt,
            hash);
    }

    public PasswordVerificationResult Verify(string password, string hash)
    {
        if (password is null || !PhcString.TryParse(hash, out var stored))
            return PasswordVerificationResult.Failed;

        if (!TryResolveAlgorithm(stored.Algorithm, out var pepperVersion))
            return PasswordVerificationResult.Failed;

        // Fails closed: verifying as unpeppered would accept the bare password against a hash never
        // made from it.
        if (!PasswordPepper.TryResolve(options.Value, pepperVersion, out var pepper))
            return PasswordVerificationResult.Failed;

        if (!stored.TryGetInt32(IterationsParameter, out var iterations) || iterations < 1 || iterations > MaxIterations)
            return PasswordVerificationResult.Failed;

        if (stored.Hash.Length > MaxHashSizeBytes)
            return PasswordVerificationResult.Failed;

        var computed = Derive(PasswordPepper.Preprocess(password, pepper), stored.Salt, iterations, stored.Hash.Length);

        if (!CryptographicOperations.FixedTimeEquals(computed, stored.Hash))
            return PasswordVerificationResult.Failed;

        return NeedsRehash(stored, iterations, pepperVersion)
            ? PasswordVerificationResult.SucceededRehashNeeded
            : PasswordVerificationResult.Succeeded;
    }

    private static bool TryResolveAlgorithm(string algorithm, out string? pepperVersion)
    {
        pepperVersion = null;

        if (string.Equals(algorithm, AlgorithmName, StringComparison.Ordinal))
            return true;

        if (!algorithm.StartsWith(PepperedAlgorithmPrefix, StringComparison.Ordinal))
            return false;

        var version = algorithm[PepperedAlgorithmPrefix.Length..];
        if (version.Length == 0 || !version.All(char.IsLetterOrDigit))
            return false;

        pepperVersion = version;
        return true;
    }

    private bool NeedsRehash(PhcString stored, int iterations, string? pepperVersion)
    {
        var settings = options.Value;
        var activeVersion = PasswordPepper.ActiveVersion(settings);

        return iterations < settings.Pbkdf2Iterations
            || stored.Salt.Length < settings.SaltSizeBytes
            || stored.Hash.Length < settings.HashSizeBytes
            || !string.Equals(pepperVersion, activeVersion, StringComparison.Ordinal);
    }

    private static byte[] Derive(byte[] secret, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, length);
}
