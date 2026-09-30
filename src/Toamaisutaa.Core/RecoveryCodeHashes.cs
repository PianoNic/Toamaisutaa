using System.Security.Cryptography;
using System.Text;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Keyed rather than plain SHA-256 because a code is only about fifty bits, so a copied table falls
/// to one GPU sweep; the key is derived so the TOTP encryption key is never also a MAC key.
/// </summary>
internal static class RecoveryCodeHashes
{
    private static readonly byte[] Purpose = "toamaisutaa:recovery-codes"u8.ToArray();

    internal const int UnkeyedVersion = 0;

    internal const int KeyedVersion = 1;

    internal static string Hash(ToamaisutaaTwoFactorOptions options, string normalizedCode)
    {
        if (string.IsNullOrWhiteSpace(options.EncryptionKey))
            throw new InvalidOperationException("TwoFactor:EncryptionKey is not set, so there is no key to store recovery codes under.");

        return Keyed(Convert.FromBase64String(options.EncryptionKey), normalizedCode);
    }

    /// <summary>Retired keys and the unkeyed hash are still tried so a rotation does not invalidate
    /// anybody's printed codes.</summary>
    internal static IEnumerable<(string Hash, int Version)> Candidates(ToamaisutaaTwoFactorOptions options, string normalizedCode)
    {
        if (!string.IsNullOrWhiteSpace(options.EncryptionKey))
            yield return (Keyed(Convert.FromBase64String(options.EncryptionKey), normalizedCode), KeyedVersion);

        foreach (var retired in options.RetiredEncryptionKeys.Values)
            yield return (Keyed(Convert.FromBase64String(retired), normalizedCode), KeyedVersion);

        if (options.AcceptUnkeyedRecoveryCodes)
            yield return (SecureTokens.HashToken(normalizedCode), UnkeyedVersion);
    }

    private static string Keyed(byte[] encryptionKey, string normalizedCode)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, encryptionKey, 32, info: Purpose);
        return Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(normalizedCode)));
    }
}
