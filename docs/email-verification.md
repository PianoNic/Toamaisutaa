# Email verification and changing an address

Two endpoints and one rule: **the account moves only when a token that was mailed to the new address
comes back.** Asking changes nothing, mail proves control, redemption writes it.

```csharp
builder.Services.AddSingleton<IEmailVerificationNotifier, YourEmailSender>();
```

Optional, like `IInvitationNotifier` and unlike `IPasswordResetNotifier`. Registering it is what
maps the two endpoints - neither exists on the wire without it. Calling
`IPasswordAccountService.RequestEmailChangeAsync` without one throws, at the call site rather than
at startup.

If SMTP is what you want, `Toamaisutaa.Email.Smtp` supplies a notifier:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpEmailVerification();
```

`Email:Smtp:EmailVerificationLinkTemplate` is checked at startup, the same as the reset and
invitation links, unless you register your own `IEmailVerificationEmailTemplate`.

## The two endpoints

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/email` | 204, 400, 409, or 429. Authenticated. Only mapped when an `IEmailVerificationNotifier` is registered |
| POST | `/auth/email/verify` | 204, 400, or 409. Anonymous, but only usable with a valid token |

**`POST /auth/email`** - authenticated. `currentPassword` is required, and the address does not move.
A verification link goes to `newEmail`, and only there.

```json
{ "newEmail": "ada@newplace.example", "currentPassword": "the one they signed in with" }
```

**`POST /auth/email/verify`** - anonymous, because the link is opened from a mailbox and often on
another device. The token is what proves anything here.

```json
{ "token": "the token from the notifier" }
```

Both answer 409 when another local account holds the address **and has proven it**, or holds it as a
user name from before user names could not contain `@`. That is checked twice: when the link is
asked for, so a link that cannot work is never sent, and again when it is redeemed, because the link
may have sat unread while somebody else proved the address. An address another account only typed
in, and never verified, is not a 409: redeeming the link proves this account holds it, and releases
it from the other.

That makes the link's wording matter. Its recipient is the mailbox's owner, who may well be the
other account - somebody who registered with their own address and never verified it. A routine
"confirm your address" would get clicked, and the address would move to whoever asked. So in that
case `IEmailVerificationNotifier` is called with `EmailVerificationContext.TakesFromAnotherAccount`,
and the SMTP template sends a different message: that somebody wants the address on their account,
that it is currently on another one which may be the reader's, and not to use the link unless they
asked. It names no account, since a user name is whatever the asker typed.

A notifier of your own should implement the overload taking the context; the default drops it.

`POST /auth/email` answers 429 in two cases, each with an `errors` body saying which: the per-address
rate limit, and a per-account cooldown of `LocalLogin:MailRequestCooldown` (a minute by default)
between links, so one account cannot mail an inbox without pause.

## Asking for the link again

There is no separate resend endpoint. `POST /auth/email` with the address the account **already
has** is a re-verification: same body, same password, same link, and redeeming it stamps the address
confirmed without moving anything. Asked again inside the cooldown it answers 429, so a resend
button should wait that long after the last one.

That is also how a freshly registered account gets its address verified in the first place - nothing
verifies an address on its own, because nothing in this package sends mail on its own.

## What redemption writes

- `ToamaisutaaPasswordCredentials.Email` and `NormalizedEmail` - the login identifier. The new
  address signs in from that moment; the old one does not.
- `ToamaisutaaPasswordCredentials.EmailConfirmedAt` - the moment it was proven.
- `ToamaisutaaUsers.Email` - the profile field, so the reset and invitation notifiers stop
  addressing mail to where this account used to be.
- On any other account holding the same address unverified: its credential's `Email` and
  `NormalizedEmail` are cleared. It typed the address in and never proved it; this account just did.
  An `email-address-released` [audit event](/audit-events) names that account, the address, and who
  took it, which is the moment to tell it.

**Sessions stay alive.** Proving an address is not a credential change, so the security stamp does
not move and nobody is signed out. A *password* change, by contrast, revokes the sessions and also
retires any outstanding verification link.

## A reset needs a verified address

On by default. `/auth/password/forgot` issues nothing for a credential whose address was never
verified, and an administrator-set password is refused for it rather than mailed to it. A mistyped
address - `anna@gmial.com` - belongs to whoever owns the typo, and a reset link or a password sent
there is the account.

The response is still 204, so the log line naming `EmailNotVerified`, with the user id and the
option's name, is the only way to diagnose "no mail arrived".

Accounts an administrator creates are best made with an [invitation](/provisioning-accounts), which
proves the mailbox the moment it is accepted. Accounts that register themselves verify at
`/auth/email` while they still know their password.

::: danger Upgrading takes password reset away from every unverified account
This used to be off. Every credential created before you upgrade has `EmailConfirmedAt` null unless it
went through `/auth/email` or an invitation, so all of those lose password reset, and the way back is
`/auth/email`, which needs the password they came here without. Ask them to verify while they can
still sign in, or keep the old behaviour, knowing what it hands to a typo's owner:

```json
{ "LocalLogin": { "RequireVerifiedEmailForPasswordReset": false } }
```
:::

Startup refuses the one configuration that has no way out at all: the option on with no
`IEmailVerificationNotifier` registered, where no address can ever be verified and so no password
can ever be reset.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:EmailVerificationTokenLifetime` | `1.00:00:00` | Single use |
| `LocalLogin:RequireVerifiedEmailForPasswordReset` | `true` | Read the warning above before upgrading |
| `Email:Smtp:EmailVerificationLinkTemplate` | none | `{token}` is replaced by the raw token. Only the default template reads it |

Expired rows are swept by `AddToamaisutaaTokenCleanup()` along with every other expiring row this
package writes.
