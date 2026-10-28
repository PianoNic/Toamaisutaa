namespace Toamaisutaa.Core;

/// <summary>What a TOTP secret is bound to: its owner's id, so it decrypts in that user's row only.</summary>
internal static class SecretBinding
{
    internal static byte[] For(Guid userId) => userId.ToByteArray();
}
