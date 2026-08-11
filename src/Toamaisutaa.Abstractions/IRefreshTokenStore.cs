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

    /// <summary>Deletes spent and expired rows. Nothing calls this unless the application opts into
    /// the cleanup service or schedules it itself.</summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
