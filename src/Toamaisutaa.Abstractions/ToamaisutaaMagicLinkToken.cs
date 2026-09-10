namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, and stored hashed exactly as password reset tokens are. The shape is
/// the same because the guarantee is: whoever reads the mailbox holds it, and holding it once is
/// all it is good for.
/// </summary>
/// <remarks>
/// It is a stronger credential than a reset token, though, and that is why its lifetime is shorter.
/// A reset link asks for a new password before it gives anything away; this one is exchanged for a
/// token pair directly, so the window in which a forwarded email is a session is the window this row
/// is alive.
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
