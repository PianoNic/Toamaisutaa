namespace Toamaisutaa.Abstractions;

public interface IRefreshTokenStore
{
    Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>Marks a token as exchanged. Presenting it again is the reuse signal.</summary>
    /// <returns>
    /// True only when this call is the one that moved the row from live - neither rotated nor revoked
    /// - to rotated, in a single conditional write. False when another request got there first.
    /// </returns>
    /// <remarks>
    /// Must be conditional: an unconditional write lets two concurrent refreshes both through and
    /// forks the family without either being detected as reuse.
    /// </remarks>
    Task<bool> MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default);

    /// <summary>Revokes every live token in the chain. Called when reuse is detected, on the
    /// assumption that one of the two holders is not the account owner.</summary>
    Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// The one row of a family with neither <c>RotatedAt</c> nor <c>RevokedAt</c> set, or null when
    /// the family has been signed out, revoked or never existed.
    /// </summary>
    /// <remarks>
    /// A family has at most one live row by construction; treat more than one as a bug rather than picking.
    /// </remarks>
    Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The live row of every family this user has, which is what a user thinks of as "my sessions".
    /// </summary>
    /// <remarks>
    /// No default implementation: an empty default would hide live sessions from their owner.
    /// </remarks>
    Task<IReadOnlyList<ToamaisutaaRefreshToken>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves a family's second-factor state forward after a step-up. Returns false when the family
    /// has no live row, which is how a step-up on a signed-out session is refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The one in-place mutation of a refresh row; call it only from the step-up path. Apply it to
    /// the family's live row, not a token id, because the client may have refreshed since its access
    /// token was minted and the freshness would otherwise vanish at the next refresh.
    /// </para>
    /// <para>
    /// No default implementation: a no-op would make step-up appear to succeed and silently expire
    /// one access-token lifetime later.
    /// </para>
    /// </remarks>
    Task<bool> UpdateSecondFactorAsync(
        Guid familyId,
        string authenticationMethods,
        string twoFactorSource,
        DateTimeOffset secondFactorAt,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes rows whose <c>ExpiresAt</c> is at or before <paramref name="expiredBefore"/>,
    /// rotated or not. Nothing calls this unless the application opts into the cleanup service or
    /// schedules it itself.</summary>
    /// <remarks>
    /// Pass a cutoff well before now, as the cleanup service does: rotated rows are what reuse
    /// detection works from while the family can still be refreshed.
    /// </remarks>
    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
