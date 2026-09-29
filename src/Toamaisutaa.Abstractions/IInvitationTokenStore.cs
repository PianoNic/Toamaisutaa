namespace Toamaisutaa.Abstractions;

public interface IInvitationTokenStore
{
    Task CreateAsync(ToamaisutaaInvitationToken token, CancellationToken cancellationToken = default);

    Task<ToamaisutaaInvitationToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the token in one conditional write. True only when this call spent it; false
    /// when another request already had. The flow acts on nothing until this says true.</summary>
    Task<bool> MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
