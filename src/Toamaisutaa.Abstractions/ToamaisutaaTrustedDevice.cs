namespace Toamaisutaa.Abstractions;

/// <summary>
/// One issued device token. A trusted device is a <b>cached second factor and nothing more</b>: it
/// never substitutes for the first factor, and it never survives anything that would have
/// invalidated the second one.
/// </summary>
/// <remarks>
/// Opaque random bytes rather than a signed token, for the same reason as the two-factor challenge:
/// a token that cannot be presented as a bearer token has no bypass to defend against.
/// <para>
/// Rotated on every use with reuse detection, exactly like a refresh token. A presented-but-already
/// -rotated device token means two parties hold the chain, and one of them is not the account owner.
/// </para>
/// </remarks>
public class ToamaisutaaTrustedDevice
{
    public Guid Id { get; set; }

    /// <summary>
    /// Stable across rotations, and the identifier a user actually sees and revokes.
    /// <see cref="Id"/> changes every time the token rotates, so a list endpoint keyed on it would
    /// hand out identifiers that stop working after the next sign-in.
    /// </summary>
    public Guid FamilyId { get; set; }

    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the raw token, unsalted. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// The user's <see cref="ToamaisutaaUser.SecurityStamp"/> when this family was established,
    /// compared on every use. This single field is what makes every credential change revoke device
    /// trust without each of them having to remember to.
    /// </summary>
    public string SecurityStamp { get; set; } = default!;

    /// <summary>
    /// When a second factor was last actually presented on this family - a TOTP code or a recovery
    /// code, never a device token. Becomes <c>toa_2fa_at</c>, so a device-trusted sign-in reports
    /// the original live challenge rather than now, and a step-up policy can tell the difference.
    /// </summary>
    public DateTimeOffset SecondFactorAt { get; set; }

    /// <summary>Supplied by the application. This package does not invent one.</summary>
    public string? Label { get; set; }

    /// <summary>Raw and truncated. Deliberately not parsed into a friendly name - that is either a
    /// dependency or a lookup table that rots.</summary>
    public string? UserAgent { get; set; }

    /// <summary>Null unless <c>TrustedDevices:IpAddressStorage</c> says otherwise.</summary>
    public string? IpAddress { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When the family started. Rotation does not move it, so a device used every week still
    /// expires - the same reason refresh families have an absolute lifetime.
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
