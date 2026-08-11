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

    /// <summary>
    /// The user's <see cref="ToamaisutaaUser.SecurityStamp"/> as it stood when this chain was
    /// minted. Compared on every refresh, and a mismatch revokes the family - which is what makes a
    /// password change or a disabled second factor end sessions that were established before it.
    /// </summary>
    public string SecurityStamp { get; set; } = default!;

    /// <summary>
    /// The RFC 8176 methods that established this chain, space-separated, replayed into the
    /// <c>amr</c> claim of every token rotated out of it. Carried rather than recomputed so that a
    /// refresh cannot quietly downgrade a session that presented a second factor into one that only
    /// ever proved a password.
    /// </summary>
    public string AuthenticationMethods { get; set; } = string.Empty;

    /// <summary>
    /// How the second factor was satisfied when this chain was established, replayed into
    /// <c>toa_2fa_source</c>. Carried for the same reason as the methods: a rotation that recomputed
    /// it would report the wrong answer, and one that dropped it would break a step-up policy one
    /// access-token lifetime after a successful sign-in.
    /// </summary>
    public string? TwoFactorSource { get; set; }

    /// <summary>The last live second factor on this chain, replayed into <c>toa_2fa_at</c>.</summary>
    public DateTimeOffset? SecondFactorAt { get; set; }

    /// <summary>Set when this token was exchanged. A token that arrives with this already set has
    /// been presented twice, which is the reuse signal.</summary>
    public DateTimeOffset? RotatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }
}
