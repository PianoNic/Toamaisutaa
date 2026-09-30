namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, stored hashed. Names the address it proves control of, which may not
/// yet be the account's current address.
/// </summary>
public class ToamaisutaaEmailVerificationToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>
    /// The address this token was mailed to, as typed. Redeeming writes it onto the credential.
    /// </summary>
    public string Email { get; set; } = default!;

    /// <summary>SHA-256 of the raw token. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set the moment it is spent. A second attempt with the same token fails.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
