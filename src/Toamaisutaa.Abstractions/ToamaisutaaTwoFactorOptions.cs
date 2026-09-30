namespace Toamaisutaa.Abstractions;

/// <summary>Everything read from the <c>TwoFactor</c> configuration section.</summary>
public sealed class ToamaisutaaTwoFactorOptions
{
    /// <summary>
    /// Base64, at least 32 bytes. Required once two-factor is registered. Separate from the token
    /// signing key.
    /// </summary>
    /// <remarks>
    /// Losing it means every enrolled user must enrol again: TOTP secrets are encrypted under it and
    /// cannot be re-derived.
    /// </remarks>
    public string? EncryptionKey { get; set; }

    /// <summary>Stamped on every row this key encrypts, so a rotation can tell them apart.</summary>
    public string EncryptionKeyVersion { get; set; } = "1";

    /// <summary>Superseded keys, kept only so rows written before a rotation still decrypt. Each row
    /// is re-encrypted under the current key the next time it is used.</summary>
    public IDictionary<string, string> RetiredEncryptionKeys { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

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

    /// <summary>
    /// How recent a sign-in has to be to enrol without the current password.
    /// </summary>
    public TimeSpan EnrolmentProofWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long a begun enrolment can still be confirmed, bounding how long a secret handed out in
    /// the clear stays usable. Past it, the enrolment has to begin again with a new secret.
    /// </summary>
    public TimeSpan EnrolmentLifetime { get; set; } = TimeSpan.FromMinutes(15);

    public int RecoveryCodeCount { get; set; } = 10;

    /// <summary>At or below this many unused codes, a redemption tells the caller to regenerate.</summary>
    public int RecoveryCodeLowWaterMark { get; set; } = 3;

    /// <summary>
    /// Whether a recovery code stored before codes were keyed - a row with a <c>HashVersion</c> of 0 -
    /// is still accepted. On by default, so nobody's printout stops working on upgrade.
    /// </summary>
    /// <remarks>
    /// Those rows are plain SHA-256 of a fifty-bit code, which a copy of the table gives up to one
    /// GPU sweep. Turn this off once few enough remain to ask their owners to regenerate.
    /// </remarks>
    public bool AcceptUnkeyedRecoveryCodes { get; set; } = true;

    /// <summary>How long the half-finished sign-in stays usable.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

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
