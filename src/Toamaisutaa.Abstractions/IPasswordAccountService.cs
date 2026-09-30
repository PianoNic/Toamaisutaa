namespace Toamaisutaa.Abstractions;

public interface IPasswordAccountService
{
    Task<AccountResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets or changes the password of an existing account, including one that arrived through an
    /// identity provider and has never had one. <paramref name="currentPassword"/> is required when
    /// a credential already exists and must be absent when it does not.
    /// </summary>
    /// <remarks>
    /// <c>authenticatedAt</c> is when the caller last actually authenticated, not a token refresh. A
    /// first password is refused unless it falls inside <c>LocalLogin:FirstPasswordProofWindow</c>,
    /// so a stolen access token cannot become a permanent way in.
    /// </remarks>
    Task<AccountResult> SetPasswordAsync(
        Guid userId,
        string? currentPassword,
        string newPassword,
        DateTimeOffset? authenticatedAt = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a reset token and hands it to the notifier. A silent no-op for an unknown address and
    /// for an account with no local credential, because an identity provider owns that one's
    /// password. Never reveals which case it was.
    /// </summary>
    Task<PasswordResetRequestOutcome> RequestPasswordResetAsync(string email, CancellationToken cancellationToken = default);

    Task<AccountResult> ResetPasswordAsync(string resetToken, string newPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a local account on someone else's behalf, without signing anyone in. Omit
    /// <paramref name="password"/> to have one generated; either way the raw value goes to
    /// <see cref="IAdminPasswordIssuedNotifier"/> and is never returned from this call.
    /// </summary>
    Task<AccountResult> AdminCreateAccountAsync(string userName, string? email, string? password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Overwrites <paramref name="userId"/>'s password with no current-password check and revokes
    /// every local session the account holds. Omit <paramref name="password"/> to have one generated;
    /// either way the raw value goes to <see cref="IAdminPasswordIssuedNotifier"/> and is never
    /// returned from this call.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The notifier is handed the credential's own address, never the profile's. With
    /// <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForPasswordReset"/> on, an
    /// unverified address refuses the call before anything changes.
    /// </para>
    /// <para>
    /// A notifier that throws leaves the password set and every session gone, and reports
    /// <see cref="AccountResult.NotificationFailed"/>; set a password again once delivery works.
    /// </para>
    /// </remarks>
    Task<AccountResult> AdminSetPasswordAsync(Guid userId, string? password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a verification token for <paramref name="newEmail"/> and hands it to
    /// <see cref="IEmailVerificationNotifier"/>. Nothing on the account moves until the token comes
    /// back to <see cref="VerifyEmailAsync"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="currentPassword"/> is always required, so a borrowed session cannot point an
    /// account at a mailbox of its own.
    /// </remarks>
    Task<AccountResult> RequestEmailChangeAsync(Guid userId, string newEmail, string currentPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Redeems a verification token: writes the address it names onto the credential and stamps
    /// <see cref="ToamaisutaaPasswordCredential.EmailConfirmedAt"/>. One indistinguishable failure for
    /// a token that is unknown, already used or expired.
    /// </summary>
    Task<AccountResult> VerifyEmailAsync(string verificationToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a magic-link token and hands it to <see cref="IMagicLinkNotifier"/>. A silent no-op
    /// for an unknown address, for an account an identity provider owns, and for an address nobody
    /// has verified. Never reveals which case it was.
    /// </summary>
    /// <remarks>
    /// The verified-address rule is not configurable: the link is exchanged for a session, so
    /// sending it to an unproven address could hand the account to whoever owns that mailbox.
    /// </remarks>
    Task<MagicLinkRequestOutcome> RequestMagicLinkAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reserves an account with nothing but an email - no user name, no credential - and hands an
    /// invitation token to <see cref="IInvitationNotifier"/>. Never returned from this call.
    /// </summary>
    /// <remarks>
    /// An address with an open invitation reuses that reservation and retires its earlier links. A
    /// notifier that throws deletes a new reservation and sets
    /// <see cref="AccountResult.NotificationFailed"/>; a reused one stays.
    /// </remarks>
    Task<AccountResult> CreateInvitationAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Withdraws the open invitation for <paramref name="email"/>: retires its links and removes the
    /// reserved account. False when there is none - an address with no invitation, or one already
    /// completed into an account, which this never touches.
    /// </summary>
    Task<bool> RevokeInvitationAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the one reserved account an invitation token names: sets the user name and password
    /// the person chose, and signs them in like <see cref="RegisterAsync"/>. One indistinguishable
    /// failure for a token that is unknown, already used or expired.
    /// </summary>
    Task<AccountResult> CompleteInvitationAsync(string invitationToken, string userName, string password, CancellationToken cancellationToken = default);
}

/// <summary>For the log, not for the caller. Every one of these answers 204.</summary>
public enum PasswordResetRequestOutcome
{
    Sent,
    UnknownEmail,

    /// <summary>The account exists but is owned by an identity provider, so there is no password
    /// here to reset.</summary>
    NoLocalCredential,

    /// <summary>The token was issued and stored, but <see cref="IPasswordResetNotifier"/> threw.</summary>
    NotificationFailed,

    /// <summary>
    /// <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForPasswordReset"/> is on and
    /// nobody has proven this address.
    /// </summary>
    EmailNotVerified,
}

/// <summary>For the log, not for the caller. Every one of these answers 204.</summary>
public enum MagicLinkRequestOutcome
{
    Sent,
    UnknownEmail,

    /// <summary>The account exists but is owned by an identity provider, which signing in here
    /// would step around.</summary>
    NoLocalCredential,

    /// <summary>
    /// Nobody has proven this address; verify it through <c>/auth/email</c> first.
    /// </summary>
    EmailNotVerified,

    /// <summary>The token was issued and stored, but <see cref="IMagicLinkNotifier"/> threw.</summary>
    NotificationFailed,
}

public sealed record AccountResult
{
    public required bool Succeeded { get; init; }

    /// <summary>Safe to show the caller: validation messages about the password they chose.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    public Guid? UserId { get; init; }

    public TokenPair? Tokens { get; init; }

    /// <summary>The user name or email is already taken, answered as 409 rather than 400.</summary>
    public bool Conflict { get; init; }

    /// <summary>
    /// The notifier carrying the secret this call produced threw, so nothing was delivered.
    /// Independent of <see cref="Succeeded"/>: <see cref="IPasswordAccountService.AdminSetPasswordAsync"/>
    /// keeps the change and reports true, <see cref="IPasswordAccountService.CreateInvitationAsync"/>
    /// rolls its reservation back and reports false. Either way the endpoint answers 502.
    /// </summary>
    public bool NotificationFailed { get; init; }

    public static AccountResult Failure(params string[] errors) => new() { Succeeded = false, Errors = errors };

    public static AccountResult Taken(string error) => new() { Succeeded = false, Conflict = true, Errors = [error] };
}
