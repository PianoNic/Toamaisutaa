namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, and stored hashed exactly as password reset tokens are. Names the one
/// <see cref="ToamaisutaaUser"/> row it completes - a placeholder created with an email and no
/// <see cref="ToamaisutaaPasswordCredential"/>, not an open invitation anyone can redeem into a new
/// account of their choosing.
/// </summary>
public class ToamaisutaaInvitationToken
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
