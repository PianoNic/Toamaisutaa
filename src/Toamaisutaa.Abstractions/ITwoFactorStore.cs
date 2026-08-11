namespace Toamaisutaa.Abstractions;

public interface ITwoFactorStore
{
    Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default);

    Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default);

    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Records the accepted time step, which is what makes a replay fail.</summary>
    Task RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default);
}

public interface IRecoveryCodeStore
{
    /// <summary>Replaces the whole set. Regenerating must invalidate every previous code, not add
    /// to them.</summary>
    Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default);

    Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default);

    Task MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default);
}

public interface ITwoFactorChallengeStore
{
    Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default);

    Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
