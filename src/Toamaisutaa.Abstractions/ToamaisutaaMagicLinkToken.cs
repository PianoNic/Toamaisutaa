namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, and stored hashed exactly as password reset tokens are.
/// </summary>
/// <remarks>
/// Shorter-lived than a reset token because it is exchanged for a token pair directly, so its
/// lifetime is the window in which a forwarded email is a session.
/// </remarks>
public class ToamaisutaaMagicLinkToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the raw token. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set the moment it is spent. A second attempt with the same token fails.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
