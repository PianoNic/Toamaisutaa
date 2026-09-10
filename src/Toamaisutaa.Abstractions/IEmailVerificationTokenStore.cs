namespace Toamaisutaa.Abstractions;

public interface IEmailVerificationTokenStore
{
    Task CreateAsync(ToamaisutaaEmailVerificationToken token, CancellationToken cancellationToken = default);

    Task<ToamaisutaaEmailVerificationToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>Spends every outstanding token for a user, so asking for a second address retires
    /// the link that was sent to the first.</summary>
    Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
