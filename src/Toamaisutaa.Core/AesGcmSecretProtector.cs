using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Encrypted rather than hashed because the TOTP secret has to be readable to generate the codes it
/// is checked against.
/// </summary>
internal sealed class AesGcmSecretProtector : ISecretProtector
{
    private readonly byte[] _activeKey;
    private readonly string _activeVersion;
    private readonly Dictionary<string, byte[]> _retired;

    public AesGcmSecretProtector(IOptions<ToamaisutaaTwoFactorOptions> options)
    {
        var settings = options.Value;

        _activeVersion = settings.EncryptionKeyVersion;
        _activeKey = string.IsNullOrWhiteSpace(settings.EncryptionKey)
            ? []
            : Convert.FromBase64String(settings.EncryptionKey);

        _retired = settings.RetiredEncryptionKeys.ToDictionary(
            entry => entry.Key,
            entry => Convert.FromBase64String(entry.Value),
            StringComparer.Ordinal);
    }

    public ProtectedSecret Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (_activeKey.Length == 0)
            throw new InvalidOperationException("TwoFactor:EncryptionKey is not set, so there is nothing to encrypt a TOTP secret with.");

        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using var aes = new AesGcm(_activeKey, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return new ProtectedSecret(ciphertext, nonce, tag, _activeVersion);
    }

    /// <summary>
    /// Marks a row bound to its user, so one presented without the mark cannot be read as an older
    /// unbound row: the tag was computed over the user's id, and decrypting without it fails.
    /// </summary>
    private const string BoundSuffix = ":u";

    public ProtectedSecret Protect(byte[] plaintext, byte[] associatedData)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(associatedData);

        if (_activeKey.Length == 0)
            throw new InvalidOperationException("TwoFactor:EncryptionKey is not set, so there is nothing to encrypt a TOTP secret with.");

        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using var aes = new AesGcm(_activeKey, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new ProtectedSecret(ciphertext, nonce, tag, _activeVersion + BoundSuffix);
    }

    public byte[] Unprotect(ProtectedSecret secret, byte[] associatedData)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(associatedData);

        // Written before rows were bound; NeedsRewrap binds it the next time it is read.
        if (!secret.KeyVersion.EndsWith(BoundSuffix, StringComparison.Ordinal))
            return Unprotect(secret);

        var key = Resolve(secret.KeyVersion[..^BoundSuffix.Length])
            ?? throw new InvalidOperationException(
                $"No key for version '{secret.KeyVersion[..^BoundSuffix.Length]}' is configured, so this enrolment cannot be "
                + "read. Put the key back under TwoFactor:RetiredEncryptionKeys, or the affected users have to enrol "
                + "again - a TOTP secret cannot be re-derived.");

        var plaintext = new byte[secret.Ciphertext.Length];

        using var aes = new AesGcm(key, secret.Tag.Length);
        aes.Decrypt(secret.Nonce, secret.Ciphertext, secret.Tag, plaintext, associatedData);

        return plaintext;
    }

    public byte[] Unprotect(ProtectedSecret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        if (secret.KeyVersion.EndsWith(BoundSuffix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"This TOTP secret (key version '{secret.KeyVersion}') is bound to its user, so it can only be decrypted "
                + "with that user's id. Call the overload that takes associatedData.");
        }

        var key = Resolve(secret.KeyVersion)
            ?? throw new InvalidOperationException(
                $"No key for version '{secret.KeyVersion}' is configured, so this enrolment cannot be read. Put the key "
                + "back under TwoFactor:RetiredEncryptionKeys, or the affected users have to enrol again - a TOTP "
                + "secret cannot be re-derived.");

        var plaintext = new byte[secret.Ciphertext.Length];

        using var aes = new AesGcm(key, secret.Tag.Length);
        aes.Decrypt(secret.Nonce, secret.Ciphertext, secret.Tag, plaintext);

        return plaintext;
    }

    public bool NeedsRewrap(string keyVersion) =>
        _activeKey.Length > 0 && !string.Equals(keyVersion, _activeVersion + BoundSuffix, StringComparison.Ordinal);

    /// <summary>
    /// The active version is only consulted once an active key is configured; otherwise a retired
    /// entry matching the active version name is shadowed and every stored value stops decrypting.
    /// </summary>
    private byte[]? Resolve(string version)
    {
        if (_activeKey.Length > 0 && string.Equals(version, _activeVersion, StringComparison.Ordinal))
            return _activeKey;

        return _retired.TryGetValue(version, out var retired) ? retired : null;
    }
}
