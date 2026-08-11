using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// RFC 6238, HMAC-SHA1, which is what every authenticator app implements. Composed entirely from
/// BCL primitives: the algorithm is a keyed hash, a big-endian counter and a modulo, and none of
/// those are worth a dependency.
/// </summary>
internal sealed class TotpProvider(IOptions<ToamaisutaaTwoFactorOptions> options) : ITotpProvider
{
    public bool TryVerify(byte[] secret, string code, DateTimeOffset now, long? lastUsedStep, out long matchedStep)
    {
        ArgumentNullException.ThrowIfNull(secret);

        matchedStep = 0;
        var settings = options.Value;

        if (string.IsNullOrWhiteSpace(code))
            return false;

        var trimmed = code.Trim().Replace(" ", string.Empty);

        if (trimmed.Length != settings.Digits || !trimmed.All(char.IsAsciiDigit))
            return false;

        var currentStep = StepAt(now, settings.Period);
        var matched = false;

        // Every candidate step is checked even after one matches. Returning early would make the
        // loop take a different amount of time depending on which step was right, which is a
        // (small, but free to avoid) signal about the drift between the two clocks.
        for (var offset = -settings.DriftSteps; offset <= settings.DriftSteps; offset++)
        {
            var step = currentStep + offset;

            // Replay protection. A code from a step already accepted is refused even though it is
            // still arithmetically valid, which closes the window where an observed code stays
            // usable for the rest of its drift period.
            if (lastUsedStep is { } used && step <= used)
                continue;

            var expected = Compute(secret, step, settings.Digits);

            if (FixedTimeEquals(expected, trimmed) && !matched)
            {
                matched = true;
                matchedStep = step;
            }
        }

        return matched;
    }

    public string BuildUri(byte[] secret, string issuer, string account)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(account);

        var settings = options.Value;
        var label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}";

        return $"otpauth://totp/{label}"
            + $"?secret={Encode(secret)}"
            + $"&issuer={Uri.EscapeDataString(issuer)}"
            + $"&algorithm=SHA1"
            + $"&digits={settings.Digits.ToString(CultureInfo.InvariantCulture)}"
            + $"&period={((int)settings.Period.TotalSeconds).ToString(CultureInfo.InvariantCulture)}";
    }

    public string Encode(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return Base32.Encode(secret);
    }

    private static long StepAt(DateTimeOffset now, TimeSpan period) =>
        now.ToUnixTimeSeconds() / (long)period.TotalSeconds;

    private static string Compute(byte[] secret, long step, int digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);

        Span<byte> hash = stackalloc byte[HMACSHA1.HashSizeInBytes];
        HMACSHA1.HashData(secret, counter, hash);

        // Dynamic truncation, RFC 4226 section 5.3: the low nibble of the last byte picks where to
        // read four bytes from, and the top bit is masked off so the result is never negative.
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        var modulo = (int)Math.Pow(10, digits);
        return (binary % modulo).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    /// <summary>
    /// The comparison is constant-time for the same reason every other comparison in this package
    /// is: a candidate is being checked against a secret-derived value, and an early exit reports
    /// how much of it was right.
    /// </summary>
    private static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(expected),
            System.Text.Encoding.ASCII.GetBytes(actual));
}
