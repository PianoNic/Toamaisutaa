namespace Toamaisutaa.Abstractions;

public interface IPasswordAccountService
{
    Task<AccountResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets or changes the password of an existing account, including one that arrived through an
    /// identity provider and has never had one. <paramref name="currentPassword"/> is required when
    /// a credential already exists and must be absent when it does not.
    /// </summary>
    Task<AccountResult> SetPasswordAsync(Guid userId, string? currentPassword, string newPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a reset token and hands it to the notifier. A silent no-op for an unknown address and
    /// for an account with no local credential, because an identity provider owns that one's
    /// password. Never reveals which case it was.
    /// </summary>
    Task<PasswordResetRequestOutcome> RequestPasswordResetAsync(string email, CancellationToken cancellationToken = default);

    Task<AccountResult> ResetPasswordAsync(string resetToken, string newPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a local account on someone else's behalf. Never signs anyone in - the caller is
    /// provisioning an account, not authenticating as its owner. <paramref name="password"/> is
    /// optional: omit it and Toamaisutaa generates one. Either way, the raw value goes to
    /// <see cref="IAdminPasswordIssuedNotifier"/> and is never returned from this call.
    /// </summary>
    Task<AccountResult> AdminCreateAccountAsync(string userName, string? email, string? password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Overwrites <paramref name="userId"/>'s password unconditionally - no current-password check,
    /// because the caller is acting on someone else's account, not their own. Revokes every local
    /// session the account holds, the same as a self-service change. <paramref name="password"/> is
    /// optional: omit it and Toamaisutaa generates one. Either way, the raw value goes to
    /// <see cref="IAdminPasswordIssuedNotifier"/> and is never returned from this call.
    /// </summary>
    Task<AccountResult> AdminSetPasswordAsync(Guid userId, string? password, CancellationToken cancellationToken = default);
}

/// <summary>For the log, not for the caller. Every one of these answers 204.</summary>
public enum PasswordResetRequestOutcome
{
    Sent,
    UnknownEmail,

    /// <summary>The account exists but is owned by an identity provider, so there is no password
    /// here to reset. Grep for this when someone reports that no mail arrived.</summary>
    NoLocalCredential,

    /// <summary>The token was issued and stored, but <see cref="IPasswordResetNotifier"/> threw.
    /// Grep for this when someone reports that no mail arrived and the account is local.</summary>
    NotificationFailed,
}

public sealed record AccountResult
{
    public required bool Succeeded { get; init; }

    /// <summary>Safe to show the caller: validation messages about the password they chose.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    public Guid? UserId { get; init; }

    public TokenPair? Tokens { get; init; }

    /// <summary>The user name or email is already taken. Separated from a validation failure only
    /// so the endpoint can answer 409 rather than 400.</summary>
    public bool Conflict { get; init; }

    public static AccountResult Failure(params string[] errors) => new() { Succeeded = false, Errors = errors };

    public static AccountResult Taken(string error) => new() { Succeeded = false, Conflict = true, Errors = [error] };
}
