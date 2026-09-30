using System.Security.Cryptography;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class RecoveryCodeProvider : IRecoveryCodeProvider
{
    // RFC 4648 base32 excludes 0, 1, 8 and 9, which get confused with O, I, B and g in handwriting.
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private const int CodeLength = 10;

    public IReadOnlyList<string> Generate(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);

        var codes = new List<string>(count);

        // A duplicate would stop working the first time its twin is spent.
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

    internal static string Normalize(string value) =>
        value.Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();

    private static string Format(string raw) => $"{raw[..5]}-{raw[5..]}";
}
