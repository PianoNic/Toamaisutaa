namespace Toamaisutaa.Core;

/// <summary>
/// RFC 4648 base32, without padding, as authenticator apps expect a manually typed TOTP secret.
/// </summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    internal static string Encode(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
            return string.Empty;

        var output = new char[(value.Length * 8 + 4) / 5];
        var written = 0;
        var buffer = 0;
        var bits = 0;

        foreach (var b in value)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                bits -= 5;
                output[written++] = Alphabet[(buffer >> bits) & 0x1F];
            }
        }

        if (bits > 0)
            output[written++] = Alphabet[(buffer << (5 - bits)) & 0x1F];

        return new string(output, 0, written);
    }

    internal static bool TryDecode(string value, out byte[] decoded)
    {
        decoded = [];

        if (string.IsNullOrEmpty(value))
            return false;

        var bytes = new List<byte>(value.Length * 5 / 8);
        var buffer = 0;
        var bits = 0;

        foreach (var c in value)
        {
            if (c is '=' or ' ' or '-')
                continue;

            var index = Alphabet.IndexOf(char.ToUpperInvariant(c));
            if (index < 0)
                return false;

            buffer = (buffer << 5) | index;
            bits += 5;

            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)((buffer >> bits) & 0xFF));
            }
        }

        decoded = [.. bytes];
        return true;
    }
}
