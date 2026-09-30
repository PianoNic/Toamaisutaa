namespace Toamaisutaa.Abstractions;

/// <summary>
/// One issued refresh token. Stored as a hash, never in the clear, and rotated on every use.
/// </summary>
/// <remarks>
/// Every rotation stays in the same <see cref="FamilyId"/>, so presenting an already-rotated token
/// proves two parties hold the chain and the whole family can be revoked.
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
    /// The user's <see cref="ToamaisutaaUser.SecurityStamp"/> when this chain was minted. A mismatch
    /// on refresh revokes the family, which is what ends sessions after a credential change.
    /// </summary>
    public string SecurityStamp { get; set; } = default!;

    /// <summary>
    /// The RFC 8176 methods that established this chain, space-separated, replayed into <c>amr</c>.
    /// Carried rather than recomputed so a refresh cannot downgrade a second-factor session to a
    /// password-only one.
    /// </summary>
    public string AuthenticationMethods { get; set; } = string.Empty;

    /// <summary>
    /// How the second factor was satisfied when this chain was established, replayed into
    /// <c>toa_2fa_source</c>. Carried because recomputing or dropping it on rotation breaks step-up
    /// policies one access-token lifetime after sign-in.
    /// </summary>
    public string? TwoFactorSource { get; set; }

    /// <summary>The last live second factor on this chain, replayed into <c>toa_2fa_at</c>.</summary>
    public DateTimeOffset? SecondFactorAt { get; set; }

    /// <summary>
    /// Raw and truncated. Carried across rotations rather than taken again, because a background
    /// refresh timer would otherwise overwrite it with whatever last renewed the session.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>Null unless <c>LocalLogin:IpAddressStorage</c> says otherwise. Carried across
    /// rotations for the same reason as <see cref="UserAgent"/>.</summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// When this row was minted; for the family's live row, the session's last activity.
    /// </summary>
    public DateTimeOffset LastUsedAt { get; set; }

    /// <summary>Set when this token was exchanged. A token that arrives with this already set has
    /// been presented twice, which is the reuse signal.</summary>
    public DateTimeOffset? RotatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }
}
