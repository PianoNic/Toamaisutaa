using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>RFC 6238 with HMAC-SHA1, which is what every authenticator app implements.</summary>
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

        // No early return on a match, so timing does not reveal which step was right.
        for (var offset = -settings.DriftSteps; offset <= settings.DriftSteps; offset++)
        {
            var step = currentStep + offset;

            // Replay protection: an observed code must not stay usable for the rest of its drift window.
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

        // Dynamic truncation, RFC 4226 section 5.3.
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        var modulo = (int)Math.Pow(10, digits);
        return (binary % modulo).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    private static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(expected),
            System.Text.Encoding.ASCII.GetBytes(actual));
}
