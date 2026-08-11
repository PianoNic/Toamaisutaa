using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// PBKDF2-HMAC-SHA256, entirely from the base class library, with an optional pepper.
/// </summary>
/// <remarks>
/// <para>
/// This is the only hasher the package ships, and the reason is dependency policy rather than
/// cryptographic preference: nothing third-party belongs in the credential path of a library other
/// people consume, and .NET has no in-box Argon2 - the runtime delegates primitives to the platform
/// and only OpenSSL implements it, so there is none coming.
/// </para>
/// <para>
/// Be clear about the cost: PBKDF2 is compute-hard, not memory-hard, so it is materially weaker
/// than Argon2id against an attacker with GPUs. A consumer who would rather take the dependency
/// registers their own <see cref="IPasswordHasher"/> before password login is added. Because every
/// row names its own algorithm, the two interoperate and existing rows migrate themselves through
/// <see cref="PasswordVerificationResult.SucceededRehashNeeded"/>.
/// </para>
/// <para>
/// A configured pepper turns the stored value into
/// <c>PBKDF2(HMAC-SHA256(pepper, password), salt)</c>, and the version that produced it is written
/// into the algorithm name. That is what lets a pepper be introduced, or rotated, without a
/// migration: rows made under the old arrangement still verify, and each one is rewritten under the
/// new one the next time its owner logs in.
/// </para>
/// </remarks>
public sealed class Pbkdf2PasswordHasher(IOptions<ToamaisutaaLocalLoginOptions> options) : IPasswordHasher
{
    internal const string AlgorithmName = "pbkdf2-sha256";
    internal const string PepperedAlgorithmPrefix = AlgorithmName + "-p";
    private const string IterationsParameter = "i";

    // A stored row is ours, but a database an attacker can write is a database that can ask this
    // process to spend a minute in a key derivation. Bound what a row may request.
    private const int MaxIterations = 50_000_000;
    private const int MaxHashSizeBytes = 1024;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var settings = options.Value;
        var pepper = ActivePepper(settings);

        var salt = RandomNumberGenerator.GetBytes(settings.SaltSizeBytes);
        var secret = Preprocess(password, pepper);
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

        // A row peppered with a key this deployment no longer holds cannot be checked. Fail closed:
        // the alternative is verifying it as though it were unpeppered, which would accept the bare
        // password against a hash that was never made from it.
        if (!TryResolvePepper(pepperVersion, out var pepper))
            return PasswordVerificationResult.Failed;

        if (!stored.TryGetInt32(IterationsParameter, out var iterations) || iterations < 1 || iterations > MaxIterations)
            return PasswordVerificationResult.Failed;

        if (stored.Hash.Length > MaxHashSizeBytes)
            return PasswordVerificationResult.Failed;

        var computed = Derive(Preprocess(password, pepper), stored.Salt, iterations, stored.Hash.Length);

        if (!CryptographicOperations.FixedTimeEquals(computed, stored.Hash))
            return PasswordVerificationResult.Failed;

        return NeedsRehash(stored, iterations, pepperVersion)
            ? PasswordVerificationResult.SucceededRehashNeeded
            : PasswordVerificationResult.Succeeded;
    }

    /// <summary>Recognises both the plain and the peppered algorithm names, and nothing else - a row
    /// written by an Argon2 hasher is not ours to verify.</summary>
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

    private bool TryResolvePepper(string? version, out byte[]? pepper)
    {
        pepper = null;

        if (version is null)
            return true;

        var settings = options.Value;

        // The active version only means anything while there is an active pepper. Without this,
        // taking the pepper out of the configuration while keeping the old key in RetiredPeppers
        // leaves the retired entry shadowed by an empty active slot, and every existing row stops
        // verifying - the one path that is supposed to make removing a pepper survivable.
        var hasActivePepper = !string.IsNullOrWhiteSpace(settings.Pepper);

        var encoded = hasActivePepper && string.Equals(version, settings.PepperVersion, StringComparison.Ordinal)
            ? settings.Pepper
            : settings.RetiredPeppers.TryGetValue(version, out var retired) ? retired : null;

        if (string.IsNullOrWhiteSpace(encoded))
            return false;

        try
        {
            pepper = Convert.FromBase64String(encoded);
            return pepper.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[]? ActivePepper(ToamaisutaaLocalLoginOptions settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Pepper))
            return null;

        // Startup validation has already rejected a malformed value, so anything reaching here is
        // decodable.
        return Convert.FromBase64String(settings.Pepper);
    }

    /// <summary>
    /// Without a pepper the password goes straight into PBKDF2. With one, it is first reduced to a
    /// 32-byte HMAC under a key that is not in the database.
    /// </summary>
    private static byte[] Preprocess(string password, byte[]? pepper)
    {
        var bytes = Encoding.UTF8.GetBytes(password);

        return pepper is null ? bytes : HMACSHA256.HashData(pepper, bytes);
    }

    /// <summary>Anything weaker than, or older than, what is configured now gets rewritten while the
    /// plaintext is still in hand.</summary>
    private bool NeedsRehash(PhcString stored, int iterations, string? pepperVersion)
    {
        var settings = options.Value;
        var activeVersion = string.IsNullOrWhiteSpace(settings.Pepper) ? null : settings.PepperVersion;

        return iterations < settings.Pbkdf2Iterations
            || stored.Salt.Length < settings.SaltSizeBytes
            || stored.Hash.Length < settings.HashSizeBytes
            || !string.Equals(pepperVersion, activeVersion, StringComparison.Ordinal);
    }

    private static byte[] Derive(byte[] secret, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, length);
}
