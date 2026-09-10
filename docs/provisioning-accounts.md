# Provisioning accounts

Three flows, one shape: a secret exists in the clear for exactly one in-process call to an interface
you implement, and never reaches an HTTP response or a log line. Nothing you install for
authentication implements any of them - sending mail, or generating a credentials sheet, is not an
authentication library's job. The opt-in `Toamaisutaa.Email.Smtp` package is the exception, and it
is a separate package for exactly that reason.

## Password reset delivery is yours

`IPasswordResetNotifier` is required and has no default implementation - startup fails without one.
Requesting a reset always answers 204, for an unknown address, for an account owned by an identity
provider, and for a notifier that threw alike. The log says which, and that line is the only way
anyone diagnoses "no email ever arrived" - including when the reason is your notifier failing, not
the account.

Writing your own is one method. If SMTP is enough, `Toamaisutaa.Email.Smtp` is an opt-in package
that supplies one instead:

```bash
dotnet add package Toamaisutaa.Email.Smtp
```

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

Nothing else changes: it is a plain `IPasswordResetNotifier`, so the package still ships no default
and nothing about local login treats it specially. Host, port, sender address and the reset link
template are checked at startup the same way the rest of `LocalLogin` is.

## Admin-provisioned accounts

`AdminCreateAccountAsync` and `AdminSetPasswordAsync` - `POST /auth/users` and
`POST /auth/users/{userId}/password` - let an authenticated caller create or overwrite someone
else's credentials. Neither ever returns a password, typed or generated: the raw value is handed to
`IAdminPasswordIssuedNotifier` instead, in process, and never appears on the wire.

```csharp
builder.Services.AddSingleton<IAdminPasswordIssuedNotifier, YourCredentialSheetGenerator>();
```

Optional, unlike `IPasswordResetNotifier`: an application that never provisions accounts for someone
else does not need to register one to use local login at all. Registering it is also what maps the
two endpoints - neither exists on the wire without it, the same reasoning `/auth/register` uses for
`AllowSelfRegistration`. Calling either method directly without one registered throws, at the call
site rather than at startup, because the feature itself is optional.

If emailing the password is what you want, `Toamaisutaa.Email.Smtp` supplies a notifier that does:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpAdminPasswordEmail();
```

Two calls rather than one, because the second is what puts the two endpoints on the wire, and an
application that installed the package to send reset mail did not ask for them. `Email:Smtp:SignInUrl`
is put at the end of the message when it is set.

**Never called for a password a person chose for themselves.** Self-registration, a self-service
change or reset, and completing a reserved invitation never reach `IAdminPasswordIssuedNotifier` -
there is no code path from any of them to it. The only two ways a password reaches that interface
are the two methods named above.

`AdminSetPasswordAsync` needs no current password, because the caller is acting on someone else's
account - and revokes every local session the account holds, the same as a self-service change.

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
endpoints at all. The raw token exists in the clear only for the one call into
`IInvitationNotifier` - never on the wire, and `POST /auth/invitations` never returns it.

`Toamaisutaa.Email.Smtp` supplies this one too, and the same way:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpInvitationEmail();
```

`Email:Smtp:InvitationLinkTemplate` is the page the email points at, with `{token}` replaced by the
raw token, and startup fails without it - the same way the reset link template is handled, and for
the same reason: the shipped template cannot invent a page it knows nothing about.

**Not open registration.** A token names exactly one reserved row; completing it can only ever set
that one account's user name and password, never create an arbitrary new one. A taken user name
answers 409 and leaves the token unconsumed, so the same person can simply try again.

`InvitationTokenLifetime` defaults to seven days - longer than `PasswordResetTokenLifetime`,
because an invitation waits on someone who was not expecting it. Expired rows are deleted by
[`AddToamaisutaaTokenCleanup()`](/password-login#expired-tokens-accumulate-unless-you-sweep-them)
along with the rest.
