namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, and stored hashed exactly as password reset tokens are. Names the one
/// address it proves control of, which is not necessarily the address the account currently has -
/// a change to a new address is written only when the token mailed there comes back.
/// </summary>
public class ToamaisutaaEmailVerificationToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>
    /// The address this token was mailed to, as it was typed. Redeeming writes it onto the
    /// credential, so the address and the proof of control are one row and cannot drift apart.
    /// </summary>
    public string Email { get; set; } = default!;

    /// <summary>SHA-256 of the raw token. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set the moment it is spent. A second attempt with the same token fails.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
