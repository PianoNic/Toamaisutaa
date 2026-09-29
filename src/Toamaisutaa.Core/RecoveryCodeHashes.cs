using System.Security.Cryptography;
using System.Text;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Recovery codes are stored as an HMAC under a key derived from <c>TwoFactor:EncryptionKey</c>,
/// not as a plain hash.
/// </summary>
/// <remarks>
/// <para>
/// A code is ten characters over a 32-symbol alphabet - about fifty bits, short on purpose, because
/// a person types it from paper. That is plenty against guessing online and nowhere near enough
/// against a copy of the table: plain SHA-256 let one sweep of 2^50 recover every user's codes in
/// about a day on a GPU. Keyed, the table alone is worth nothing without the key it was hashed under.
/// </para>
/// <para>
/// Derived rather than used directly, so the key that encrypts TOTP secrets is never also the key
/// of a MAC. Retired keys and the old unkeyed hash are still tried on the way in, so a rotation, or
/// codes issued before this existed, do not stop anybody's printout from working.
/// </para>
/// </remarks>
internal static class RecoveryCodeHashes
{
    private static readonly byte[] Purpose = "toamaisutaa:recovery-codes"u8.ToArray();

    /// <summary>What a newly issued code is stored as.</summary>
    internal static string Hash(ToamaisutaaTwoFactorOptions options, string normalizedCode)
    {
        if (string.IsNullOrWhiteSpace(options.EncryptionKey))
            throw new InvalidOperationException("TwoFactor:EncryptionKey is not set, so there is no key to store recovery codes under.");

        return Keyed(Convert.FromBase64String(options.EncryptionKey), normalizedCode);
    }

    /// <summary>Every form a code still in use could be stored as, current key first.</summary>
    internal static IEnumerable<string> Candidates(ToamaisutaaTwoFactorOptions options, string normalizedCode)
    {
        if (!string.IsNullOrWhiteSpace(options.EncryptionKey))
            yield return Keyed(Convert.FromBase64String(options.EncryptionKey), normalizedCode);

        foreach (var retired in options.RetiredEncryptionKeys.Values)
            yield return Keyed(Convert.FromBase64String(retired), normalizedCode);

        yield return SecureTokens.HashToken(normalizedCode);
    }

    private static string Keyed(byte[] encryptionKey, string normalizedCode)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, encryptionKey, 32, info: Purpose);
        return Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(normalizedCode)));
    }
}
