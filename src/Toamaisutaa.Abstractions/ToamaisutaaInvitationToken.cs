namespace Toamaisutaa.Abstractions;

/// <summary>
/// Single-use, time-limited, stored hashed. Completes exactly one placeholder
/// <see cref="ToamaisutaaUser"/> row that has no <see cref="ToamaisutaaPasswordCredential"/> yet.
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

    /// <summary>
    /// The address the invitation was sent to, which completing it proves. Read from here rather than
    /// the user row, whose email a provider sync can rewrite. Null on older rows, which fall back to
    /// the user row.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>What an open invitation is found by when the same address is invited again or revoked.</summary>
    public string? NormalizedEmail { get; set; }
}
