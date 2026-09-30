namespace Toamaisutaa.Abstractions;

/// <summary>
/// One issued device token. A trusted device is a <b>cached second factor and nothing more</b>: it
/// never substitutes for the first factor, and it never survives anything that would have
/// invalidated the second one.
/// </summary>
/// <remarks>
/// Opaque random bytes rather than a signed token, so it can never be presented as a bearer token.
/// Rotated on every use with reuse detection, like a refresh token.
/// </remarks>
public class ToamaisutaaTrustedDevice
{
    public Guid Id { get; set; }

    /// <summary>
    /// Stable across rotations, and the identifier a user sees and revokes. <see cref="Id"/> changes
    /// on every rotation.
    /// </summary>
    public Guid FamilyId { get; set; }

    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the raw token, unsalted. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// The user's <see cref="ToamaisutaaUser.SecurityStamp"/> when this family was established,
    /// compared on every use, so any credential change revokes device trust.
    /// </summary>
    public string SecurityStamp { get; set; } = default!;

    /// <summary>
    /// When a second factor was last actually presented on this family, never a device token.
    /// Becomes <c>toa_2fa_at</c>, so a step-up policy sees the original live challenge rather than now.
    /// </summary>
    public DateTimeOffset SecondFactorAt { get; set; }

    /// <summary>Supplied by the application.</summary>
    public string? Label { get; set; }

    /// <summary>Raw and truncated.</summary>
    public string? UserAgent { get; set; }

    /// <summary>Null unless <c>TrustedDevices:IpAddressStorage</c> says otherwise.</summary>
    public string? IpAddress { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When the family started. Rotation does not move it, so a device used every week still expires.
    /// </summary>
    public DateTimeOffset FamilyStartedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset LastUsedAt { get; set; }

    /// <summary>Set when this token was exchanged. Arriving with it already set is the reuse
    /// signal.</summary>
    public DateTimeOffset? RotatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }
}
