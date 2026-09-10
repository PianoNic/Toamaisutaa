# Email verification and changing an address

Two endpoints and one rule: **the account moves only when a token that was mailed to the new address
comes back.** Asking changes nothing, mail proves control, redemption writes it.

```csharp
builder.Services.AddSingleton<IEmailVerificationNotifier, YourEmailSender>();
```

Optional, like `IInvitationNotifier` and unlike `IPasswordResetNotifier`: an application that never
verifies an address does not need one to use local login at all. Registering it is also what maps
the two endpoints - neither exists on the wire without it. Calling
`IPasswordAccountService.RequestEmailChangeAsync` without one throws, at the call site rather than
at startup, because the feature itself is optional.

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
| POST | `/auth/email` | 204, 400, or 409. Authenticated. Only mapped when an `IEmailVerificationNotifier` is registered |
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

Both answer 409 when another local account already holds the address, which is checked twice: when
the link is asked for, so a link that cannot work is never sent, and again when it is redeemed,
because the link may have sat unread while somebody else took the address.

## Asking for the link again

There is no separate resend endpoint. `POST /auth/email` with the address the account **already
has** is a re-verification: same body, same password, same link, and redeeming it stamps the address
confirmed without moving anything.

That is also how a freshly registered account gets its address verified in the first place - nothing
verifies an address on its own, because nothing in this package sends mail on its own.

## What redemption writes

- `ToamaisutaaPasswordCredentials.Email` and `NormalizedEmail` - the login identifier. The new
  address signs in from that moment; the old one does not.
- `ToamaisutaaPasswordCredentials.EmailConfirmedAt` - the moment it was proven.
- `ToamaisutaaUsers.Email` - the profile field, so the reset and invitation notifiers stop
  addressing mail to where this account used to be.

**Sessions stay alive.** Proving an address is not a credential change, so the security stamp does
not move and nobody is signed out. A *password* change is the other way round: it revokes the
sessions, and it also retires any outstanding verification link, because a pending change of address
is a credential in flight and a password change is the moment somebody is most likely reacting to a
break-in.

## Requiring a verified address before a password reset

Off by default:

```json
{ "LocalLogin": { "RequireVerifiedEmailForPasswordReset": true } }
```

With it on, `/auth/password/forgot` issues nothing for a credential whose address was never
verified. The response is 204 either way - the whole point of that endpoint is that a caller cannot
tell a real account from an unknown one - so the log line naming `EmailNotVerified` is the only way
anyone diagnoses "no mail arrived". It says so in one line, with the user id and the option's name.

::: danger It takes password reset away from every existing account at once
Every credential already in the database has `EmailConfirmedAt` null. Switching this on locks all of
them out of password reset, and the way back is `/auth/email`, which needs the password they came
here without. Verify the existing accounts first, or expect to reset them by hand.
:::

Startup refuses the one configuration that has no way out at all: the option on with no
`IEmailVerificationNotifier` registered, where no address can ever be verified and so no password
can ever be reset.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:EmailVerificationTokenLifetime` | `1.00:00:00` | Single use |
| `LocalLogin:RequireVerifiedEmailForPasswordReset` | `false` | Read the warning above before turning it on |
| `Email:Smtp:EmailVerificationLinkTemplate` | none | `{token}` is replaced by the raw token. Only the default template reads it |

Expired rows are swept by `AddToamaisutaaTokenCleanup()` along with every other expiring row this
package writes.
