namespace Toamaisutaa.Abstractions;

/// <summary>
/// The challenges handed back instead of tokens when an unverified address holds a sign-in back.
/// Needed only with <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForSignIn"/> on.
/// </summary>
public interface IEmailVerificationChallengeStore
{
    Task CreateAsync(ToamaisutaaEmailVerificationChallenge challenge, CancellationToken cancellationToken = default);

    Task<ToamaisutaaEmailVerificationChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the challenge in one conditional write. True only when this call spent it.</summary>
    Task<bool> MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}

/// <summary>
/// The codes the default <see cref="IEmailVerificationMethod"/> mails. Not needed when you register a
/// method of your own.
/// </summary>
public interface IEmailVerificationCodeStore
{
    Task CreateAsync(ToamaisutaaEmailVerificationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// The user's outstanding code, or with none outstanding the most recently issued, or null when none
    /// was ever issued. Outstanding first, because a new code and the one it retired can share a timestamp.
    /// </summary>
    Task<ToamaisutaaEmailVerificationCode?> FindLatestAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts one try against an unspent code before it is compared, in one conditional write, so
    /// parallel guesses cannot each find tries left. False when the code is spent or has none left.
    /// </summary>
    Task<bool> TryReserveAttemptAsync(Guid codeId, int maxAttempts, CancellationToken cancellationToken = default);

    /// <summary>Spends the code in one conditional write. True only when this call spent it.</summary>
    Task<bool> MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>Spends every outstanding code for a user, so a new one is the only one that works.</summary>
    Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
