namespace Toamaisutaa.Abstractions;

public interface IPasswordResetTokenStore
{
    Task CreateAsync(ToamaisutaaPasswordResetToken token, CancellationToken cancellationToken = default);

    Task<ToamaisutaaPasswordResetToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the token in one conditional write. True only when this call spent it; false
    /// when another request already had. The flow acts on nothing until this says true.</summary>
    Task<bool> MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>Spends every outstanding token for a user, so issuing a new one or completing a
    /// reset retires the others.</summary>
    Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
