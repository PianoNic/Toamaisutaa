using System.Security.Cryptography;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Ten characters from a 32-symbol alphabet, hyphenated in the middle: <c>7Q2FK-M9XBT</c>. Fifty
/// bits of randomness, which is far past guessable and still short enough to read off a printout.
/// </summary>
internal sealed class RecoveryCodeProvider : IRecoveryCodeProvider
{
    /// <summary>RFC 4648 base32 minus nothing - the digits it excludes (0, 1, 8, 9) are the ones
    /// that get confused with O, I, B and g in handwriting, which is the whole point.</summary>
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private const int CodeLength = 10;

    public IReadOnlyList<string> Generate(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);

        var codes = new List<string>(count);

        // A duplicate would be a code that stops working the first time its twin is spent. At fifty
        // bits it will not happen, and checking costs nothing.
        while (codes.Count < count)
        {
            var code = Format(RandomNumberGenerator.GetString(Alphabet, CodeLength));

            if (!codes.Contains(code, StringComparer.Ordinal))
                codes.Add(code);
        }

        return codes;
    }

    public bool LooksLikeRecoveryCode(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var normalized = Normalize(value);

        return normalized.Length == CodeLength
            && normalized.All(c => Alphabet.Contains(c, StringComparison.Ordinal));
    }

    /// <summary>
    /// What actually gets hashed. Hyphens, spaces and case are presentation, and somebody reading a
    /// code off paper should not fail because they typed it the way it looks rather than the way it
    /// was stored.
    /// </summary>
    internal static string Normalize(string value) =>
        value.Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();

    private static string Format(string raw) => $"{raw[..5]}-{raw[5..]}";
}
