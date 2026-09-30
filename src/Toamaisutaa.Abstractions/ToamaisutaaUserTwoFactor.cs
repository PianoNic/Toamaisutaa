namespace Toamaisutaa.Abstractions;

/// <summary>
/// One user's TOTP enrolment. Separate from the password credential so accounts without a password
/// can enrol.
/// </summary>
public class ToamaisutaaUserTwoFactor
{
    /// <summary>Primary key and foreign key both: one enrolment per user.</summary>
    public Guid UserId { get; set; }

    /// <summary>AES-256-GCM. Encrypted rather than hashed because codes are generated from the
    /// secret.</summary>
    public byte[] SecretCiphertext { get; set; } = default!;

    public byte[] SecretNonce { get; set; } = default!;

    public byte[] SecretTag { get; set; } = default!;

    /// <summary>Which key encrypted this row, so a rotation knows what to decrypt it with.</summary>
    public string EncryptionKeyVersion { get; set; } = default!;

    /// <summary>
    /// Null until the enrolment is confirmed with a working code. Presence is what "enabled" means,
    /// so a user who generated a secret but scanned nothing is not locked out.
    /// </summary>
    public DateTimeOffset? ConfirmedAt { get; set; }

    /// <summary>
    /// The last time step accepted for this user. A code must be strictly newer, so an observed code
    /// cannot be replayed within its drift period.
    /// </summary>
    public long? LastUsedStep { get; set; }

    /// <summary>
    /// Wrong codes for an account with no password credential. An account with a password counts
    /// them there instead.
    /// </summary>
    public int FailedAttemptCount { get; set; }

    public DateTimeOffset? FirstFailedAttemptAt { get; set; }

    public DateTimeOffset? LockedOutUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public bool IsEnabled => ConfirmedAt is not null;
}

/// <summary>One single-use recovery code. Hashed, never stored in the clear.</summary>
public class ToamaisutaaRecoveryCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>An HMAC under a key derived from <c>TwoFactor:EncryptionKey</c>, or unkeyed SHA-256
    /// on a row with a <see cref="HashVersion"/> of 0.</summary>
    public string CodeHash { get; set; } = default!;

    /// <summary>
    /// 1 for a keyed hash, 0 for legacy unkeyed SHA-256. Both look the same, so this is the only way
    /// to tell them apart.
    /// </summary>
    public int HashVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

/// <summary>
/// The half-finished sign-in: the first factor is proven, the second is not.
/// </summary>
/// <remarks>
/// The token behind this is opaque random bytes rather than a JWT, so it can never be presented as
/// a bearer token regardless of validation configuration.
/// </remarks>
public class ToamaisutaaTwoFactorChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the raw token. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set the moment it is spent. Presenting it again fails.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>
    /// What this challenge is for. Each endpoint refuses the other's, so a step-up challenge cannot
    /// be spent at the anonymous sign-in endpoint for a whole token pair.
    /// </summary>
    public TwoFactorChallengePurpose Purpose { get; set; }

    /// <summary>
    /// The refresh family that asked for a <see cref="TwoFactorChallengePurpose.StepUp"/> challenge.
    /// Null for <see cref="TwoFactorChallengePurpose.SignIn"/>, where there is no session yet.
    /// </summary>
    /// <remarks>
    /// Needed alongside <see cref="Purpose"/>, so a user with two sessions cannot elevate the wrong one.
    /// </remarks>
    public Guid? FamilyId { get; set; }

    /// <summary>
    /// The RFC 8176 methods already proved when this challenge was minted, space-separated, and the
    /// ones the finished sign-in's <c>amr</c> is built from.
    /// </summary>
    /// <remarks>
    /// Carried rather than assumed, so a magic-link sign-in does not claim <c>pwd</c>. Empty reads as
    /// <c>pwd</c>.
    /// </remarks>
    public string AuthenticationMethods { get; set; } = string.Empty;

    /// <summary>
    /// The user's security stamp when the challenge was issued. A challenge whose stamp no longer
    /// matches is refused, so a password reset stops a half-finished sign-in from being completed.
    /// Null on older rows, which are accepted until they expire.
    /// </summary>
    public string? SecurityStamp { get; set; }
}

/// <summary>Which ceremony a challenge belongs to. Not interchangeable.</summary>
public enum TwoFactorChallengePurpose
{
    /// <summary>Finishing a sign-in that stopped for a second factor. Redeemed anonymously.</summary>
    SignIn,

    /// <summary>Elevating a session that is already signed in. Redeemed by that session only.</summary>
    StepUp,
}
