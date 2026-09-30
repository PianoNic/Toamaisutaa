using System.Security.Cryptography;

namespace Toamaisutaa.Core;

internal static class AdminPasswordGenerator
{
    // Excludes characters confused in handwriting or a monospace font (0/O, 1/l/I).
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    private const int Length = 16;

    internal static string Generate() => RandomNumberGenerator.GetString(Alphabet, Length);
}
