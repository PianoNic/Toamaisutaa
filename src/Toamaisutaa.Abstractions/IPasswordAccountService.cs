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
    /// <remarks>
    /// The revocation happens before the notifier is called and does not depend on it. A notifier
    /// that throws leaves the password set and every session gone, and says so through
    /// <see cref="AccountResult.NotificationFailed"/> - the value reached nobody, so set one again
    /// once delivery works.
    /// </remarks>
    Task<AccountResult> AdminSetPasswordAsync(Guid userId, string? password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a verification token for <paramref name="newEmail"/> and hands it to
    /// <see cref="IEmailVerificationNotifier"/>, which mails it there rather than to the address the
    /// account currently has. Nothing on the account moves until the token comes back to
    /// <see cref="VerifyEmailAsync"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="currentPassword"/> is required even when <paramref name="newEmail"/> is the
    /// address already on the credential, which is how a verification link is asked for a second
    /// time. One rule rather than two, and the second address is the one that matters: whoever holds
    /// a borrowed session should not be able to point an account at a mailbox of their own.
    /// </remarks>
    Task<AccountResult> RequestEmailChangeAsync(Guid userId, string newEmail, string currentPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Redeems a verification token: writes the address it names onto the credential and stamps
    /// <see cref="ToamaisutaaPasswordCredential.EmailConfirmedAt"/>. A silent, single failure for a
    /// token that is unknown, already used or expired, the same reasoning
    /// <see cref="ResetPasswordAsync"/> uses.
    /// </summary>
    Task<AccountResult> VerifyEmailAsync(string verificationToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a magic-link token and hands it to <see cref="IMagicLinkNotifier"/>. A silent no-op
    /// for an unknown address, for an account an identity provider owns, and for an address nobody
    /// has verified. Never reveals which case it was.
    /// </summary>
    /// <remarks>
    /// The verified-address rule is not an option and does not have one. Every other token this
    /// package mails leads somewhere that asks for a password next; this one is exchanged for a
    /// session, so sending it to an address that is a typo, or that somebody else now owns, hands
    /// them the account.
    /// </remarks>
    Task<MagicLinkRequestOutcome> RequestMagicLinkAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reserves an account with nothing but an email - no user name, no credential - and hands an
    /// invitation token to <see cref="IInvitationNotifier"/>. Never returned from this call.
    /// </summary>
    /// <remarks>
    /// A notifier that throws takes the reservation with it: the row and its token are deleted and
    /// <see cref="AccountResult.NotificationFailed"/> is set. Nothing here looks for an existing
    /// reservation before making one, so leaving the row behind would mean a retry reserved the
    /// same address twice.
    /// </remarks>
    Task<AccountResult> CreateInvitationAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the one reserved account an invitation token names: sets the user name and password
    /// the person chose, and signs them in - the same shape <see cref="RegisterAsync"/> answers with.
    /// A silent, single failure for a token that is unknown, already used or expired, the same
    /// reasoning <see cref="ResetPasswordAsync"/> uses.
    /// </summary>
    Task<AccountResult> CompleteInvitationAsync(string invitationToken, string userName, string password, CancellationToken cancellationToken = default);
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

    /// <summary>
    /// <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForPasswordReset"/> is on and
    /// nobody has proven this address. Grep for this when someone reports that no mail arrived,
    /// the account is local, and the option was switched on over an existing database.
    /// </summary>
    EmailNotVerified,
}

/// <summary>For the log, not for the caller. Every one of these answers 204, the same as
/// <see cref="PasswordResetRequestOutcome"/> and for the same reason.</summary>
public enum MagicLinkRequestOutcome
{
    Sent,
    UnknownEmail,

    /// <summary>The account exists but is owned by an identity provider. Signing in here would step
    /// around the provider that owns the account. Grep for this when someone reports that no mail
    /// arrived.</summary>
    NoLocalCredential,

    /// <summary>
    /// Nobody has proven this address, so a link that is itself a session may not be sent to it.
    /// Grep for this when someone reports that no mail arrived and the account is local: the way
    /// forward is <c>/auth/email</c>.
    /// </summary>
    EmailNotVerified,

    /// <summary>The token was issued and stored, but <see cref="IMagicLinkNotifier"/> threw. Grep
    /// for this when someone reports that no mail arrived and the address is verified.</summary>
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

    /// <summary>
    /// The notifier carrying the secret this call produced threw, so nothing was delivered.
    /// Independent of <see cref="Succeeded"/>: <see cref="IPasswordAccountService.AdminSetPasswordAsync"/>
    /// keeps the change and reports true, <see cref="IPasswordAccountService.CreateInvitationAsync"/>
    /// rolls its reservation back and reports false. Either way the endpoint answers 502 rather
    /// than a 500 or a success the caller would read as "the mail went out".
    /// </summary>
    public bool NotificationFailed { get; init; }

    public static AccountResult Failure(params string[] errors) => new() { Succeeded = false, Errors = errors };

    public static AccountResult Taken(string error) => new() { Succeeded = false, Conflict = true, Errors = [error] };
}
