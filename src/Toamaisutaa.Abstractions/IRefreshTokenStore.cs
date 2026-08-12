namespace Toamaisutaa.Abstractions;

public interface IRefreshTokenStore
{
    Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>Marks a token as exchanged. Presenting it again is the reuse signal.</summary>
    Task MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default);

    /// <summary>Revokes every live token in the chain. Called when reuse is detected, on the
    /// assumption that one of the two holders is not the account owner.</summary>
    Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// The one row of a family with neither <c>RotatedAt</c> nor <c>RevokedAt</c> set, or null when
    /// the family has been signed out, revoked or never existed.
    /// </summary>
    /// <remarks>
    /// Two jobs, one read: it answers "is this session still alive" for step-up, and it hands back
    /// the <c>AuthenticationMethods</c> that the step-up has to union into rather than overwrite.
    /// A family has at most one live row by construction - a rotation marks the old one rotated
    /// before creating the next - and an implementation should treat more than one as a bug rather
    /// than picking.
    /// </remarks>
    Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves a family's second-factor state forward after a step-up. Returns false when the family
    /// has no live row, which is how a step-up on a signed-out session is refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The one in-place mutation of a refresh row in this package.</b> Everything else rotates.
    /// Reach for it only from the step-up path.
    /// </para>
    /// <para>
    /// Keyed on the family and applied to its live row - the one with neither <c>RotatedAt</c> nor
    /// <c>RevokedAt</c> set - rather than on a token id. A client may refresh between receiving its
    /// access token and stepping up, so the row the token was minted alongside is already rotated;
    /// updating that one would leave the live row stale and the freshness would vanish at the next
    /// refresh. That is the bug this whole path exists to prevent, reintroduced by the fix for it.
    /// </para>
    /// <para>
    /// <b>No default implementation, deliberately.</b> This breaks a consumer with a store of their
    /// own, and a default that quietly did nothing would make step-up appear to succeed and expire
    /// one access-token lifetime later with nothing failing in between. A compile error is the
    /// cheaper failure.
    /// </para>
    /// </remarks>
    Task<bool> UpdateSecondFactorAsync(
        Guid familyId,
        string authenticationMethods,
        string twoFactorSource,
        DateTimeOffset secondFactorAt,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes spent and expired rows. Nothing calls this unless the application opts into
    /// the cleanup service or schedules it itself.</summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
