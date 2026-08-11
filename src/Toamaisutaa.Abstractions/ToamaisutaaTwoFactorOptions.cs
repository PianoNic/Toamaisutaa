namespace Toamaisutaa.Abstractions;

/// <summary>Everything read from the <c>TwoFactor</c> configuration section.</summary>
public sealed class ToamaisutaaTwoFactorOptions
{
    // ── Encryption at rest ──

    /// <summary>
    /// Base64, at least 32 bytes. Required once two-factor is registered.
    /// </summary>
    /// <remarks>
    /// Its own key rather than the token signing key. Purpose separation is standard, the two rotate
    /// on different schedules, and the signing key may one day become an RSA private key for
    /// asymmetric validation - which cannot also be an AES-256-GCM key.
    /// <para>
    /// Losing it means every enrolled user must enrol again. A TOTP secret has to be recoverable to
    /// be used, so it is encrypted rather than hashed, and there is no way to re-derive one.
    /// </para>
    /// </remarks>
    public string? EncryptionKey { get; set; }

    /// <summary>Stamped on every row this key encrypts, so a rotation can tell them apart.</summary>
    public string EncryptionKeyVersion { get; set; } = "1";

    /// <summary>Superseded keys, kept only so rows written before a rotation still decrypt. Each row
    /// is re-encrypted under the current key the next time it is used.</summary>
    public IDictionary<string, string> RetiredEncryptionKeys { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

    // ── TOTP ──

    /// <summary>Do not change this. Authenticator apps assume six.</summary>
    public int Digits { get; set; } = 6;

    /// <summary>Do not change this. Authenticator apps assume thirty seconds.</summary>
    public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Steps either side of now that are accepted, for clock drift. 1 means a code is
    /// usable for about ninety seconds.</summary>
    public int DriftSteps { get; set; } = 1;

    /// <summary>RFC 4226 recommends 160 bits, which is what authenticator apps expect.</summary>
    public int SecretSizeBytes { get; set; } = 20;

    /// <summary>The name the authenticator app shows. Defaults to the application's name.</summary>
    public string? Issuer { get; set; }

    // ── Recovery codes ──

    public int RecoveryCodeCount { get; set; } = 10;

    /// <summary>At or below this many unused codes, a redemption tells the caller to regenerate.</summary>
    public int RecoveryCodeLowWaterMark { get; set; } = 3;

    // ── Challenge ──

    /// <summary>How long the half-finished sign-in stays usable.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    // ── Enforcement ──

    public TwoFactorEnforcement Enforcement { get; set; } = TwoFactorEnforcement.Optional;

    public string EnrolledPolicyName { get; set; } = "Toamaisutaa.TwoFactor";
}

public enum TwoFactorEnforcement
{
    /// <summary>Users may enrol. Nothing is enforced.</summary>
    Optional,

    /// <summary>A local sign-in by an enrolled user must complete the challenge.</summary>
    RequiredForLocalLogin,

    /// <summary>Every user should be enrolled. Tokens for the unenrolled say so, and the enrolment
    /// endpoints stay reachable so they can put it right.</summary>
    RequiredForAll,
}
