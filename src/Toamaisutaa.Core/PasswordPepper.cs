using System.Security.Cryptography;
using System.Text;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Which pepper a stored row was written under, which one new rows get, and how either is folded
/// into a password before derivation.
/// </summary>
/// <remarks>
/// Shared by every hasher rather than owned by one. "Is this key still held, and is it the current
/// one" is a single rule whose wrong answer either accepts a password against a hash that was never
/// made from it or locks a fleet out, and two copies of a rule like that drift into two answers.
/// </remarks>
internal static class PasswordPepper
{
    /// <summary>The version marker new hashes carry, or <c>null</c> while no pepper is configured.</summary>
    internal static string? ActiveVersion(ToamaisutaaLocalLoginOptions settings) =>
        string.IsNullOrWhiteSpace(settings.Pepper) ? null : settings.PepperVersion;

    internal static byte[]? Active(ToamaisutaaLocalLoginOptions settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Pepper))
            return null;

        // Startup validation has already rejected a malformed value, so anything reaching here is
        // decodable.
        return Convert.FromBase64String(settings.Pepper);
    }

    /// <summary>
    /// Finds the key a row written under <paramref name="version"/> needs. False means the key is
    /// not held, and the caller fails closed: the alternative is verifying the row as though it
    /// were unpeppered, which would accept the bare password against a hash that was never made
    /// from it.
    /// </summary>
    internal static bool TryResolve(ToamaisutaaLocalLoginOptions settings, string? version, out byte[]? pepper)
    {
        pepper = null;

        if (version is null)
            return true;

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

    /// <summary>
    /// Without a pepper the password goes straight into the derivation. With one, it is first
    /// reduced to a 32-byte HMAC under a key that is not in the database.
    /// </summary>
    internal static byte[] Preprocess(string password, byte[]? pepper)
    {
        var bytes = Encoding.UTF8.GetBytes(password);

        return pepper is null ? bytes : HMACSHA256.HashData(pepper, bytes);
    }
}
