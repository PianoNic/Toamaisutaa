namespace Toamaisutaa.Abstractions;

/// <summary>
/// One thing that happened to an account, handed to every <see cref="IAuthenticationEventSink"/>.
/// </summary>
/// <remarks>
/// A hierarchy rather than one record with nullable extras, so a sink that only cares about
/// lockouts writes one <c>is</c> pattern instead of reading a discriminator and hoping the right
/// fields are populated.
/// </remarks>
public abstract record AuthenticationEvent
{
    /// <summary>
    /// A stable name for this kind of event, for a sink that writes a column rather than switching
    /// on a type. It never changes once shipped, which a type name cannot promise.
    /// </summary>
    public abstract string Kind { get; }

    /// <summary>Read from the same clock the rest of the operation used, not from the sink's.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// Null only where there is genuinely no account to name - a sign-in attempt against an
    /// identifier nobody owns. Everything else carries one.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// The RFC 8176 <c>amr</c> values the resulting token carries. Empty on anything that issued no
    /// token, which is most of these.
    /// </summary>
    public IReadOnlyList<string> AuthenticationMethods { get; init; } = [];
}

/// <summary>A token pair was issued. <see cref="SessionId"/> is the refresh family, which is what
/// <c>toa_sid</c> carries and what <see cref="SessionRevoked"/> later names.</summary>
public sealed record SignInSucceeded : AuthenticationEvent
{
    public override string Kind => "sign-in-succeeded";

    public required Guid SessionId { get; init; }

    /// <summary>How the second factor was satisfied - see <see cref="TwoFactorSource"/> - or null
    /// when the account has none, which is not the same as failing one.</summary>
    public string? TwoFactorSource { get; init; }
}

/// <summary>
/// A sign-in did not issue anything.
/// </summary>
/// <remarks>
/// <see cref="Reason"/> is the internal outcome, not what the caller was told: the endpoints
/// collapse every failure into one response precisely so a caller cannot tell an unknown account
/// from a wrong password. A sink is on the inside of that and gets the real answer.
/// </remarks>
public sealed record SignInFailed : AuthenticationEvent
{
    public override string Kind => "sign-in-failed";

    public required SignInOutcome Reason { get; init; }
}

/// <summary>The failure that crossed the threshold, published once as the lock goes on rather than
/// on every attempt refused afterwards - those are <see cref="SignInFailed"/>.</summary>
public sealed record AccountLockedOut : AuthenticationEvent
{
    public override string Kind => "account-locked-out";

    public required DateTimeOffset LockedOutUntil { get; init; }
}

/// <summary>A password was set through a path that proved something first: the current password, or
/// an administrator's own authorisation.</summary>
public sealed record PasswordChanged : AuthenticationEvent
{
    public override string Kind => "password-changed";

    /// <summary>True when somebody else set it. The account holder did not do this, which is the
    /// distinction an audit trail is usually being read for.</summary>
    public bool SetByAdministrator { get; init; }
}

/// <summary>A password was set by spending a reset token, so the person who did it proved control
/// of the mailbox and nothing else.</summary>
public sealed record PasswordReset : AuthenticationEvent
{
    public override string Kind => "password-reset";
}

/// <summary>
/// A verification link was redeemed, so the account's login identifier and the address every reset
/// link and magic link is sent to are now the ones that link named.
/// </summary>
/// <remarks>
/// Both addresses are carried because the old one is the fact that cannot be recovered from the
/// account afterwards, and an investigation asking when the recovery mailbox moved has this row and
/// nothing else. <see cref="PreviousEmail"/> equal to <see cref="Email"/> is the first verification
/// of an address already on file: that changed the account too, because it is what makes a magic
/// link work.
/// </remarks>
public sealed record EmailChanged : AuthenticationEvent
{
    public override string Kind => "email-changed";

    /// <summary>Null for an account that had no address on file until this.</summary>
    public string? PreviousEmail { get; init; }

    public required string Email { get; init; }
}

/// <summary>An enrolment was confirmed with a working code. Beginning one publishes nothing: until
/// it is confirmed, nothing about the account has changed.</summary>
public sealed record TwoFactorEnrolled : AuthenticationEvent
{
    public override string Kind => "two-factor-enrolled";
}

public sealed record TwoFactorDisabled : AuthenticationEvent
{
    public override string Kind => "two-factor-disabled";
}

/// <summary>A second factor was presented and refused - a wrong code, an expired challenge, a
/// challenge spent twice.</summary>
public sealed record TwoFactorFailed : AuthenticationEvent
{
    public override string Kind => "two-factor-failed";

    public required SignInOutcome Reason { get; init; }
}

/// <summary>
/// A recovery code was spent, which means the authenticator is gone or unreachable.
/// </summary>
/// <remarks>
/// Worth an alert rather than a row. It is the one factor a person can hold on paper, so it is also
/// the one an attacker can hold on paper.
/// </remarks>
public sealed record RecoveryCodeUsed : AuthenticationEvent
{
    public override string Kind => "recovery-code-used";

    /// <summary>True when few codes remain, matching what the response tells the caller.</summary>
    public bool RunningLow { get; init; }
}

/// <summary>A WebAuthn credential was registered against an account, so there is now a way into it
/// that no password protects.</summary>
public sealed record PasskeyRegistered : AuthenticationEvent
{
    public override string Kind => "passkey-registered";

    /// <summary>The row id, which is what the user sees in their passkey list and deletes by. Never
    /// the credential id the authenticator uses.</summary>
    public required Guid PasskeyId { get; init; }

    public string? Label { get; init; }
}

/// <summary>A WebAuthn credential was deleted. Worth a row of its own: for an account whose only
/// credential this was, it is the moment passwordless sign-in stopped working.</summary>
public sealed record PasskeyRemoved : AuthenticationEvent
{
    public override string Kind => "passkey-removed";

    public required Guid PasskeyId { get; init; }
}

/// <summary>A device was trusted, so this account will skip its second factor there until the trust
/// expires or a credential change takes it.</summary>
public sealed record TrustedDeviceAdded : AuthenticationEvent
{
    public override string Kind => "trusted-device-added";

    /// <summary>The family id, which is what the user sees in their device list and revokes by.</summary>
    public required Guid DeviceId { get; init; }

    public string? Label { get; init; }
}

public sealed record TrustedDeviceRevoked : AuthenticationEvent
{
    public override string Kind => "trusted-device-revoked";

    /// <summary>Null when every device for the account went at once.</summary>
    public Guid? DeviceId { get; init; }

    /// <summary>The same string written to the revoked row - <c>revoked-by-user</c>,
    /// <c>password-changed</c>, <c>device-token-reuse</c> and the rest.</summary>
    public required string Reason { get; init; }
}

/// <summary>A refresh family stopped being usable, whether the user asked for it or a credential
/// change did it for them.</summary>
public sealed record SessionRevoked : AuthenticationEvent
{
    public override string Kind => "session-revoked";

    /// <summary>Null when every session for the account went at once.</summary>
    public Guid? SessionId { get; init; }

    /// <summary>The same string written to the revoked rows - <c>signed-out</c>,
    /// <c>password-changed</c>, <c>security-stamp-changed</c> and the rest.</summary>
    public required string Reason { get; init; }
}

/// <summary>
/// An already-rotated refresh token was presented, so two parties hold the chain and one of them is
/// not the account owner.
/// </summary>
/// <remarks>
/// The single most alert-worthy event here. It is published alongside the <see cref="SessionRevoked"/>
/// and <see cref="TrustedDeviceRevoked"/> that reuse detection triggers, because "a theft was
/// detected" and "these things were taken away" are different facts and an audit table wants both.
/// </remarks>
public sealed record RefreshTokenReuseDetected : AuthenticationEvent
{
    public override string Kind => "refresh-token-reuse-detected";

    public required Guid SessionId { get; init; }
}
