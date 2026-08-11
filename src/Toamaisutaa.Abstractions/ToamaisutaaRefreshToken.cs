namespace Toamaisutaa.Abstractions;

/// <summary>
/// One issued refresh token. Stored as a hash, never in the clear, and rotated on every use.
/// </summary>
/// <remarks>
/// <see cref="FamilyId"/> is what makes theft detectable. Every rotation stays in the same family,
/// so presenting a token that has already been rotated proves two parties hold the chain, and the
/// whole family can be revoked at once.
/// </remarks>
public class ToamaisutaaRefreshToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>The chain this token belongs to, and the unit of revocation when reuse is seen.</summary>
    public Guid FamilyId { get; set; }

    /// <summary>SHA-256 of the raw token. Unique, and the only thing ever compared.</summary>
    public string TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the family started. Rotation does not extend this, so a chain cannot outlive
    /// the absolute lifetime by being used often.</summary>
    public DateTimeOffset FamilyStartedAt { get; set; }

    /// <summary>Set when this token was exchanged. A token that arrives with this already set has
    /// been presented twice, which is the reuse signal.</summary>
    public DateTimeOffset? RotatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }
}
