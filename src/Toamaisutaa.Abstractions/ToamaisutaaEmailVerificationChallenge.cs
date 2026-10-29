namespace Toamaisutaa.Abstractions;

/// <summary>
/// A sign-in held back for an unverified address: what a client presents, with the proof, to finish
/// it. Single use, time-limited, stored hashed, and bound to the address and the security stamp it was
/// issued against.
/// </summary>
public class ToamaisutaaEmailVerificationChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the raw challenge. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// The credential's normalized address when this was issued. Answering it proves that address and
    /// no other, so a credential whose address has moved since cannot be confirmed with it.
    /// </summary>
    public string NormalizedEmail { get; set; } = default!;

    /// <summary>A reset or password change since it was issued moves the stamp, and the challenge stops working.</summary>
    public string? SecurityStamp { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

/// <summary>
/// A mailed verification code, kept only as a keyed hash. Single use, time-limited, and spent after
/// too many wrong tries. The default <see cref="IEmailVerificationMethod"/> writes these.
/// </summary>
public class ToamaisutaaEmailVerificationCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>The normalized address the code was mailed to. It verifies that address and no other.</summary>
    public string NormalizedEmail { get; set; } = default!;

    /// <summary>
    /// HMAC-SHA256 of the user and the code, under a key derived from the local signing key, because six
    /// digits under a plain hash fall to anyone holding a copy of the table in a millisecond.
    /// </summary>
    public string CodeHash { get; set; } = default!;

    public int FailedAttempts { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set when it is redeemed, retired by a newer code, or tried wrongly too often.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
