namespace Toamaisutaa.Abstractions;

/// <summary>
/// One user's TOTP enrolment. Its own table rather than columns on the password credential: that
/// row's defining column is a required password hash, so hanging this off it would force a user
/// whose account comes from an identity provider to carry a fake password to use a second factor.
/// </summary>
public class ToamaisutaaUserTwoFactor
{
    /// <summary>Primary key and foreign key both: one enrolment per user.</summary>
    public Guid UserId { get; set; }

    /// <summary>AES-256-GCM. Encrypted rather than hashed because a TOTP secret has to be readable
    /// to generate the codes it is checked against.</summary>
    public byte[] SecretCiphertext { get; set; } = default!;

    public byte[] SecretNonce { get; set; } = default!;

    public byte[] SecretTag { get; set; } = default!;

    /// <summary>Which key encrypted this row, so a rotation knows what to decrypt it with.</summary>
    public string EncryptionKeyVersion { get; set; } = default!;

    /// <summary>
    /// Null until the enrolment is confirmed with a working code. Presence is what "enabled" means -
    /// generating a secret must never be what switches a second factor on, or a user who scans
    /// nothing locks themselves out.
    /// </summary>
    public DateTimeOffset? ConfirmedAt { get; set; }

    /// <summary>
    /// The last time step accepted for this user. A code must be strictly newer, which closes the
    /// window where an observed code can be replayed for the rest of its drift period.
    /// </summary>
    public long? LastUsedStep { get; set; }

    /// <summary>
    /// Wrong codes counted against an account that has no password credential to count them on -
    /// one that signs in with a passkey alone, or that an identity provider owns. An account with a
    /// password counts them there instead, alongside wrong passwords.
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

    /// <summary>An HMAC under a key derived from <c>TwoFactor:EncryptionKey</c>, or, on a row with a
    /// <see cref="HashVersion"/> of 0, the unkeyed SHA-256 codes were stored as before that.</summary>
    public string CodeHash { get; set; } = default!;

    /// <summary>
    /// 1 for a keyed hash, 0 for the unkeyed SHA-256 of rows written before keying existed. Both are
    /// 32 bytes of base64, so without this nothing could tell them apart, count the old ones, or keep
    /// the unkeyed hash from being tried against a row that was never stored that way.
    /// </summary>
    public int HashVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

/// <summary>
/// The half-finished sign-in: the first factor is proven, the second is not.
/// </summary>
/// <remarks>
/// The token behind this is opaque random bytes, not a signed token. A JWT challenge would be
/// structurally a valid bearer token, kept out of the API only by a validation rule - and rules are
/// configuration, which a consumer can loosen. An opaque token cannot be presented as a bearer token
/// at all, so the bypass is impossible rather than defended against.
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
    /// What this challenge is for. Each endpoint refuses the other's, so a challenge minted for an
    /// authenticated step-up cannot be spent at the anonymous sign-in endpoint for a whole token
    /// pair.
    /// </summary>
    public TwoFactorChallengePurpose Purpose { get; set; }

    /// <summary>
    /// The refresh family that asked for a <see cref="TwoFactorChallengePurpose.StepUp"/> challenge.
    /// Null for <see cref="TwoFactorChallengePurpose.SignIn"/>, where there is no session yet.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Purpose"/> and both are needed. Purpose alone leaves a user with two
    /// sessions able to elevate the wrong one; binding alone leaves the cross-endpoint redemption
    /// open.
    /// </remarks>
    public Guid? FamilyId { get; set; }

    /// <summary>
    /// The RFC 8176 methods already proved when this challenge was minted, space-separated, and the
    /// ones the finished sign-in's <c>amr</c> is built from.
    /// </summary>
    /// <remarks>
    /// Carried rather than assumed, because there is now more than one way to reach a challenge. A
    /// magic link proves <c>email</c> and no password was typed, so writing <c>pwd</c> on the way
    /// out would put a claim on the token that nothing had earned. Empty reads as <c>pwd</c>, which
    /// is what every row written before this column existed was.
    /// </remarks>
    public string AuthenticationMethods { get; set; } = string.Empty;

    /// <summary>
    /// The user's security stamp when the challenge was issued. A challenge whose stamp no longer
    /// matches is refused: a password reset or change, or anything else that moves the stamp, is
    /// somebody reacting to another person having had access, and a half-finished sign-in that
    /// person started must not be finishable afterwards. Null on rows written before the column
    /// existed, which are accepted until they expire.
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
