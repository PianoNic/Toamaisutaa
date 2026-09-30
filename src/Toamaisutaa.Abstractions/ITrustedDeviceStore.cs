namespace Toamaisutaa.Abstractions;

public interface ITrustedDeviceStore
{
    Task<ToamaisutaaTrustedDevice?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>The newest unrotated, unrevoked row of each live family, which is what a user thinks
    /// of as "my devices".</summary>
    Task<IReadOnlyList<ToamaisutaaTrustedDevice>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default);

    Task CreateAsync(ToamaisutaaTrustedDevice device, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks the row rotated only if it is still live - not rotated, not revoked - and says whether
    /// it did. A write that landed regardless let parallel redemptions of one token each mint a live
    /// successor, and none of them ever looked like reuse.
    /// </summary>
    Task<bool> MarkRotatedAsync(Guid deviceId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default);

    Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns how many rows were revoked. Called explicitly where the security stamp cannot do the
    /// job: redeeming a recovery code, and detecting refresh-token reuse.
    /// </summary>
    Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
