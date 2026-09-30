namespace Toamaisutaa.Passkeys;

/// <summary>
/// Accepts standard base64 and either padding as well as base64url, because client encoders disagree
/// on both and rejecting one would fail passkeys on one platform only.
/// </summary>
internal static class PasskeyEncoding
{
    internal static byte[] Decode(string value)
    {
        var normalised = value.Replace('-', '+').Replace('_', '/').TrimEnd('=');

        return Convert.FromBase64String(normalised.PadRight(normalised.Length + ((4 - (normalised.Length % 4)) % 4), '='));
    }
}
