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

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public bool IsEnabled => ConfirmedAt is not null;
}

/// <summary>One single-use recovery code. Hashed, never stored in the clear.</summary>
public class ToamaisutaaRecoveryCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>Unsalted SHA-256, for the reason documented on the token helper: these are
    /// high-entropy random values, so there is no dictionary to defend against and nothing for a
    /// salt to do.</summary>
    public string CodeHash { get; set; } = default!;

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
}

/// <summary>Which ceremony a challenge belongs to. Not interchangeable.</summary>
public enum TwoFactorChallengePurpose
{
    /// <summary>Finishing a sign-in that stopped for a second factor. Redeemed anonymously.</summary>
    SignIn,

    /// <summary>Elevating a session that is already signed in. Redeemed by that session only.</summary>
    StepUp,
}
