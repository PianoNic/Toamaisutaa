# Provisioning accounts

Three flows, one shape: a secret exists in the clear for exactly one in-process call to an interface
you implement, and never reaches an HTTP response or a log line. Nothing in the core packages
implements those interfaces; the opt-in `Toamaisutaa.Email.Smtp` package can.

## Password reset delivery is yours

`IPasswordResetNotifier` is required and has no default implementation - startup fails without one.
Requesting a reset always answers 204, for an unknown address, for an account owned by an identity
provider, and for a notifier that threw alike. The log says which, and is the only way to diagnose
"no email ever arrived".

Writing your own is one method. Mail `resetToken` to `user.Email` as a link to a page of yours that
posts it, with the new password, to `/auth/password/reset`:

```csharp
public sealed class MyResetNotifier : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default) =>
        /* send https://app.example.com/reset?token={resetToken} to user.Email */ Task.CompletedTask;
}

builder.Services.AddSingleton<IPasswordResetNotifier, MyResetNotifier>();
```

If SMTP is enough, `Toamaisutaa.Email.Smtp` is an opt-in package that supplies one instead:

```bash
dotnet add package Toamaisutaa.Email.Smtp
```

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

It is a plain `IPasswordResetNotifier`. Host, port, sender address and the reset link template are
checked at startup the same way the rest of `LocalLogin` is.

| Key (`Email:Smtp:`) | Default | |
|---|---|---|
| `Host` | | Required |
| `Port` | `587` | |
| `User` / `Password` | | Leave both out for a relay that takes no login |
| `Security` | `Auto` | `Auto` uses TLS on 465 and required STARTTLS elsewhere. Also `StartTls`, `SslOnConnect`, `None` (local relay only) |
| `From` / `FromDisplayName` | | `From` is required |
| `PasswordResetLinkTemplate` | | Required. Your reset page, with `{token}` where the token goes. Every link template must be `https://` (`http://` only for localhost); prefer the token in the fragment, `https://app.example.com/reset#token={token}`, which browsers do not send to servers or put in `Referer` |
| `InvitationLinkTemplate` | | Required with `AddToamaisutaaSmtpInvitationEmail` |
| `EmailVerificationLinkTemplate` | | Required with `AddToamaisutaaSmtpEmailVerification` |
| `MagicLinkTemplate` | | Required with `AddToamaisutaaSmtpMagicLink` |
| `SignInUrl` | | Optional, put at the end of an admin-issued password mail |
| `Timeout` | `00:00:30` | |
| `SkipCertificateVerification` | `false` | Self-signed relay on a private network only |

## The admin endpoints need an admin role

`POST /auth/users`, `POST /auth/users/{userId}/password`, `POST /auth/invitations` and the
[disable, enable and revoke endpoints](#disabling-an-account) take the account they act on from the
route or the body rather than from the token, so being signed in is not enough to reach them. All of
them carry the `Toamaisutaa.Admin` policy, and that policy exists only when `Oidc:AdminRole` names a
role:

```json
{
  "Oidc": {
    "AdminRole": "admin"
  }
}
```

**With no admin role configured they are not mapped at all**, so they answer 404. A notifier
registered with no admin role configured logs a warning at startup saying exactly that.

A locally issued token carries no roles until you say so: this package ships no roles table, so
register an [`IUserRoleProvider`](/customizing-password-login#local-accounts-have-no-roles) that answers
with your own. Without one, a local account can never satisfy the policy and only a token from your
identity provider carrying the role will get through.

## Admin-provisioned accounts

::: tip Prefer an invitation
An account created here stores its address unverified, and with the default
`LocalLogin:RequireVerifiedEmailForPasswordReset` it then has no password reset, and no generated
password can be mailed to it, until its owner verifies at `/auth/email`. An
[invitation](#completing-a-reserved-invitation) proves the mailbox the moment it is accepted, and a
mistyped address only means the invitation never arrives.
:::

`AdminCreateAccountAsync` and `AdminSetPasswordAsync` - `POST /auth/users` and
`POST /auth/users/{userId}/password` - let an administrator create or overwrite someone else's
credentials. Neither ever returns a password, typed or generated: the raw value is handed to
`IAdminPasswordIssuedNotifier` instead, in process, and never appears on the wire.

```csharp
builder.Services.AddSingleton<IAdminPasswordIssuedNotifier, YourCredentialSheetGenerator>();
```

Optional, unlike `IPasswordResetNotifier`. Registering it, together with an admin role, is what maps
the two endpoints - neither exists on the wire without both. Calling either method directly without
a notifier registered throws, at the call site rather than at startup.

If emailing the password is what you want, `Toamaisutaa.Email.Smtp` supplies a notifier that does:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpAdminPasswordEmail();
```

Two calls rather than one, because the second is what puts the two endpoints on the wire.
`Email:Smtp:SignInUrl` is put at the end of the message when it is set.

**Never called for a password a person chose for themselves.** Self-registration, a self-service
change or reset, and completing a reserved invitation never reach `IAdminPasswordIssuedNotifier`;
only the two methods named above do.

`AdminSetPasswordAsync` needs no current password, because the caller is acting on someone else's
account - and revokes every local session the account holds, the same as a self-service change.

### When the notifier fails

The revocation happens before the notifier is called and does not depend on it. A notifier that
throws leaves the new password set and every session, trusted device and outstanding token gone.

What the caller gets is a **502** rather than a 204, with the package's usual error body:

```json
{
  "error": "notification_failed",
  "error_description": "The password was set and every session revoked, but ..."
}
```

Read it as "done, and nobody has the new password". If the password was generated, it is gone: set
one again once delivery works. `AccountResult.NotificationFailed` is the same signal for a caller
using the service directly.

## Disabling an account

Resetting the password of someone who is leaving does not remove them: the new password is mailed to
their own address. Disable the account instead.

| Endpoint | Service method | Does |
|---|---|---|
| `POST /auth/users/{userId}/disable` | `AdminDisableAccountAsync` | Refuses every way in and ends every session |
| `POST /auth/users/{userId}/enable` | `AdminEnableAccountAsync` | Lets the account sign in again |
| `POST /auth/users/{userId}/sessions/revoke` | `AdminRevokeSessionsAsync` | Ends every session, leaves the credentials alone |

None of them sends mail, and none needs a notifier registered: they are mapped whenever an admin role
is configured. Each answers 204, or 404 for an id that names no account.

**Disabling** sets `ToamaisutaaUser.DisabledAt`, moves the security stamp, and revokes every refresh
family, trusted device and outstanding reset, magic-link, verification and invitation link. From then
on the password, a magic link, a passkey, a second-factor challenge, a refresh and a password reset
are all refused, and nothing is mailed when one is asked for. The caller is told only that sign-in
failed. `ICurrentUser.GetOrProvisionAsync` throws `AccountDisabledException`, which the package's own
endpoints answer with a 403:

```json
{ "error": "account_disabled", "error_description": "This account is disabled." }
```

The password, passkeys and second factor are kept, so enabling gives the account back as it was.
Disabling one already disabled keeps the original `DisabledAt` and revokes again.

**Revoking sessions** is for an account you suspect, rather than one you are removing. It moves the
stamp and revokes every session and trusted device, so the owner signs in again with what they
already have.

Both move the stamp, so an access token already in flight is refused on admin endpoints, and on
every endpoint with [`LocalLogin:CheckSecurityStampOnEveryRequest`](/password-login#revoking-sessions-means-local-sessions)
on. Without it, an endpoint that only checks the token's signature accepts it until
`AccessTokenLifetime` runs out.

A custom `IUserStore` needs `SetDisabledAtAsync`. The default implementation throws, so a store written
before this existed keeps compiling and fails only when an account is actually disabled.

## Completing a reserved invitation

`CreateInvitationAsync` and `CompleteInvitationAsync` - `POST /auth/invitations` and
`POST /auth/invitations/complete` - are the other admin-provisioning mode: instead of a finished
account, an authenticated caller reserves one with nothing but an email. Toamaisutaa creates a
`ToamaisutaaUser` row with no user name and no `ToamaisutaaPasswordCredential`, and a single-use,
expiring token. The invited person, not the admin, chooses the user name and password when they
complete it - so unlike `/auth/users`, no password ever passes through the admin's hands at all.

```csharp
builder.Services.AddSingleton<IInvitationNotifier, YourInvitationEmailSender>();
```

Same shape as `IAdminPasswordIssuedNotifier`: optional, resolved lazily, and what maps the two
endpoints at all - with `POST /auth/invitations` wanting an admin role too, as above. The raw token
exists in the clear only for the one call into `IInvitationNotifier`.

`Toamaisutaa.Email.Smtp` supplies this one too, and the same way:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpInvitationEmail();
```

`Email:Smtp:InvitationLinkTemplate` is the page the email points at, with `{token}` replaced by the
raw token, and startup fails without it.

Inviting an address that already has an open invitation reuses that reservation and retires its
earlier links, so only the newest one works - a first link that leaked is dead the moment the address
is invited again. A notifier that throws takes a new reservation with it: the reserved row and its
token are deleted and `POST /auth/invitations` answers **502** with the same `notification_failed`
body. A reservation that already existed stays, with its links retired, and the retry finds it again.

`POST /auth/invitations/revoke` with `{ "email": "..." }` withdraws an open invitation: its links stop
working and the reserved account is removed. It answers **404** when the address has no open
invitation, including one already completed into an account, which it never touches. Admin role
required, like creating one.

`POST /auth/invitations/complete` is mapped whether or not an admin role is configured. It is
redeemed by the invited person, and the invitation it completes may have come from a worker calling
`CreateInvitationAsync` rather than over HTTP.

**Not open registration.** A token names exactly one reserved row; completing it can only ever set
that one account's user name and password, never create an arbitrary new one. A taken user name
answers 409 and leaves the token unconsumed, so the same person can simply try again.

`InvitationTokenLifetime` defaults to seven days - longer than `PasswordResetTokenLifetime`,
because an invitation waits on someone who was not expecting it. Expired rows are deleted by
[`AddToamaisutaaTokenCleanup()`](/password-login#expired-tokens-accumulate-unless-you-sweep-them)
along with the rest.
