namespace Toamaisutaa.Abstractions;

/// <summary>
/// One thing that happened to an account, handed to every <see cref="IAuthenticationEventSink"/>.
/// </summary>
public abstract record AuthenticationEvent
{
    /// <summary>
    /// A stable name for this kind of event that never changes once shipped, unlike a type name.
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

    /// <summary>
    /// The <c>sub</c> of whoever was signed in on the request that caused this, filled in by the
    /// publisher. Differs from <see cref="UserId"/> when an administrator acted on someone else's
    /// account; null on an anonymous request, a sign-in for example.
    /// </summary>
    public string? ActorSubject { get; init; }
}

/// <summary>An account came into existence.</summary>
public sealed record AccountCreated : AuthenticationEvent
{
    public override string Kind => "account-created";

    /// <summary><c>registration</c>, <c>administrator</c>, <c>invitation</c> or <c>external-login</c>.</summary>
    public required string Source { get; init; }
}

/// <summary>An invitation link was issued and handed to the notifier.</summary>
public sealed record InvitationSent : AuthenticationEvent
{
    public override string Kind => "invitation-sent";

    public required string Email { get; init; }
}

/// <summary>A password reset link was issued and handed to the notifier. Requests that sent nothing
/// - an unknown address, an unverified one - publish nothing, as they name no account.</summary>
public sealed record PasswordResetRequested : AuthenticationEvent
{
    public override string Kind => "password-reset-requested";
}

/// <summary>A magic sign-in link was issued and handed to the notifier.</summary>
public sealed record MagicLinkRequested : AuthenticationEvent
{
    public override string Kind => "magic-link-requested";
}

/// <summary>A verification link for a new address was issued; nothing has moved until it is redeemed.</summary>
public sealed record EmailChangeRequested : AuthenticationEvent
{
    public override string Kind => "email-change-requested";

    public required string Email { get; init; }
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
/// <see cref="Reason"/> is the internal outcome, not what the caller was told; never expose it, or
/// callers can tell an unknown account from a wrong password.
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

    /// <summary>
    /// True when only the source the wrong passwords came from is locked out, and the owner can still
    /// sign in from anywhere else.
    /// </summary>
    public bool SourceOnly { get; init; }

    /// <summary>
    /// How many locks this account has had since it last completed a sign-in, this one included. More
    /// than one means somebody holding the password keeps guessing codes: the moment to tell the owner.
    /// Always 1 for a lock on a source, which does not escalate.
    /// </summary>
    public int Strikes { get; init; } = 1;
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

/// <summary>An administrator disabled the account. Published with the <see cref="SessionRevoked"/>
/// and <see cref="TrustedDeviceRevoked"/> that disabling triggers.</summary>
public sealed record AccountDisabled : AuthenticationEvent
{
    public override string Kind => "account-disabled";
}

/// <summary>
/// Another identity provider vouched for the account at the end of a sign-in there. The sign-in itself
/// is the <see cref="SignInSucceeded"/> that follows, with <c>fed</c> in its methods, once the client
/// has exchanged its code and answered any second-factor challenge.
/// </summary>
public sealed record ExternalLoginAuthenticated : AuthenticationEvent
{
    public override string Kind => "external-login-authenticated";

    public required string ProviderKey { get; init; }
}

/// <summary>A provider was linked to the account, by its owner or by a verified address on first sign-in.</summary>
public sealed record ExternalLoginLinked : AuthenticationEvent
{
    public override string Kind => "external-login-linked";

    public required string ProviderKey { get; init; }
}

/// <summary>The account's owner removed a linked provider.</summary>
public sealed record ExternalLoginUnlinked : AuthenticationEvent
{
    public override string Kind => "external-login-unlinked";

    public required string ProviderKey { get; init; }
}

/// <summary>An administrator enabled an account that was disabled.</summary>
public sealed record AccountEnabled : AuthenticationEvent
{
    public override string Kind => "account-enabled";
}

/// <summary>
/// A verification link was redeemed, so the account's login identifier and the address every reset
/// link and magic link is sent to are now the ones that link named.
/// </summary>
/// <remarks>
/// <see cref="PreviousEmail"/> equal to <see cref="Email"/> is the first verification of an address
/// already on file.
/// </remarks>
public sealed record EmailChanged : AuthenticationEvent
{
    public override string Kind => "email-changed";

    /// <summary>Null for an account that had no address on file until this.</summary>
    public string? PreviousEmail { get; init; }

    public required string Email { get; init; }
}

/// <summary>
/// An account lost an address it held unverified, because another account proved the mailbox. The
/// moment to tell the account that lost it, since nothing else does.
/// </summary>
public sealed record EmailAddressReleased : AuthenticationEvent
{
    public override string Kind => "email-address-released";

    public required string Email { get; init; }

    /// <summary>The account that proved the mailbox and now holds the address.</summary>
    public required Guid ClaimedByUserId { get; init; }
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
/// Published alongside the <see cref="SessionRevoked"/> and <see cref="TrustedDeviceRevoked"/> that
/// reuse detection triggers.
/// </remarks>
public sealed record RefreshTokenReuseDetected : AuthenticationEvent
{
    public override string Kind => "refresh-token-reuse-detected";

    public required Guid SessionId { get; init; }
}
