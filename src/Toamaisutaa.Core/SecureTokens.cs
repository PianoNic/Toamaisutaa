using System.Security.Cryptography;
using System.Text;

namespace Toamaisutaa.Core;

internal static class SecureTokens
{
    private const int TokenSizeBytes = 32;

    internal static string Create() => Base64Url(RandomNumberGenerator.GetBytes(TokenSizeBytes));

    /// <summary>
    /// Plain unsalted SHA-256 on purpose: 256 random bits leave nothing for a KDF or salt to defend,
    /// and lookup by exact match on every refresh needs a fast hash.
    /// </summary>
    internal static string HashToken(string token) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
