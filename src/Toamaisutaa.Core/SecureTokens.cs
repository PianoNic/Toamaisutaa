using System.Security.Cryptography;
using System.Text;

namespace Toamaisutaa.Core;

/// <summary>
/// Refresh and reset tokens: generated from <see cref="RandomNumberGenerator"/>, handed out once,
/// and stored only as a SHA-256 hash.
/// </summary>
internal static class SecureTokens
{
    private const int TokenSizeBytes = 32;

    /// <summary>256 bits of randomness, URL-safe so it survives a query string or a reset link.</summary>
    internal static string Create() => Base64Url(RandomNumberGenerator.GetBytes(TokenSizeBytes));

    /// <summary>
    /// A plain unsalted SHA-256, deliberately, and not a password KDF. Do not "fix" this.
    /// </summary>
    /// <remarks>
    /// A password hash is slow because passwords are low-entropy and guessable. These tokens are 256
    /// bits straight from the system generator: there is no dictionary to try, so there is nothing
    /// for iteration count to defend against, and no two users can collide so there is nothing for a
    /// salt to do. What is left is the requirement to look one up by exact match on every refresh,
    /// which a fast hash does and a KDF would turn into a per-request cost for no security gain.
    /// </remarks>
    internal static string HashToken(string token) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
