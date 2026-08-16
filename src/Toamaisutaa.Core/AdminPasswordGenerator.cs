using System.Security.Cryptography;

namespace Toamaisutaa.Core;

/// <summary>
/// Used when an admin creates or overwrites someone else's password without choosing one. Sixteen
/// characters from a 54-symbol alphabet is around 92 bits - far past what six hundred thousand
/// rounds of PBKDF2 need defending against, so the length is about staying legible on a printout,
/// not about entropy.
/// </summary>
internal static class AdminPasswordGenerator
{
    // Same exclusions as the recovery code alphabet: characters that get confused with each other in
    // handwriting or a monospace font (0/O, 1/l/I).
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    private const int Length = 16;

    internal static string Generate() => RandomNumberGenerator.GetString(Alphabet, Length);
}
