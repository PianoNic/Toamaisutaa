namespace Toamaisutaa.Abstractions;

/// <summary>RFC 6238. Public so a consumer with an unusual authenticator can replace it.</summary>
public interface ITotpProvider
{
    /// <summary>
    /// True when the code matches within the configured drift.
    /// <paramref name="lastUsedStep"/> rejects anything at or before the last accepted step, so an
    /// observed code cannot be replayed for the rest of its window; <paramref name="matchedStep"/>
    /// returns the step that matched so the caller can store it.
    /// </summary>
    bool TryVerify(byte[] secret, string code, DateTimeOffset now, long? lastUsedStep, out long matchedStep);

    /// <summary>The <c>otpauth://totp/</c> URI an authenticator app scans.</summary>
    string BuildUri(byte[] secret, string issuer, string account);

    /// <summary>Base32, which is the encoding every authenticator app expects.</summary>
    string Encode(byte[] secret);
}

/// <summary>Generates recovery codes. Public for the same reason as the TOTP provider.</summary>
public interface IRecoveryCodeProvider
{
    IReadOnlyList<string> Generate(int count);

    /// <summary>Whether a string looks like a recovery code rather than a TOTP code, so one input
    /// field can accept either and the person typing does not have to say which they hold.</summary>
    bool LooksLikeRecoveryCode(string value);
}

/// <summary>Encrypts the TOTP secret at rest. AES-256-GCM behind an interface so the key can come
/// from somewhere else - a key vault, an HSM - without touching anything that uses it.</summary>
public interface ISecretProtector
{
    ProtectedSecret Protect(byte[] plaintext);

    /// <summary>Throws when the key that encrypted it is not available. Fails closed: verifying
    /// against a secret we cannot read is not something to guess at.</summary>
    byte[] Unprotect(ProtectedSecret secret);

    /// <summary>True when the row was written under a key that is no longer the active one, so the
    /// caller can re-encrypt it while it has the plaintext in hand.</summary>
    bool NeedsRewrap(string keyVersion);
}

public sealed record ProtectedSecret(byte[] Ciphertext, byte[] Nonce, byte[] Tag, string KeyVersion);
