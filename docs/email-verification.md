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

When another local account holds the address **and has proven it**, or holds it as a user name from
before user names could not contain `@`, no link is issued. `POST /auth/email` still answers 204, as
if one had been: a 409 would let any signed-in account find out which addresses have accounts here.
The address's owner gets `IEmailVerificationNotifier.SendAddressInUseAsync` instead - with the SMTP
package, a short mail saying someone tried to use it and nothing changed. The default sends nothing.
Redeeming checks again, and answers 409, because a link may have sat unread while somebody else
proved the address; that needs the link, so it reveals nothing new. An address another account only typed
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

That is also how a freshly registered account gets its address verified in the first place, unless
[a verified address is required to sign in](#requiring-a-verified-address-to-sign-in), in which case
registering mails a code and the account confirms before it ever signs in.

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

## Requiring a verified address to sign in

Off by default. Turn it on and registering mails a six-digit code, and the account cannot sign in with
its password until the code comes back:

```json
{ "LocalLogin": { "RequireVerifiedEmailForSignIn": true } }
```

With the SMTP package that is all - `AddToamaisutaaSmtpEmailVerification()` already sends the code.
A notifier of your own implements `IEmailVerificationNotifier.SendCodeAsync`; startup refuses the
option when the registered notifier does not, or when there is none.

### The flow

1. **`POST /auth/register`** creates the account exactly as before - a taken user name or address is
   still 409 - but answers **201 with a challenge instead of tokens**, and mails a code. `email` is
   required.
2. **`POST /auth/email/verify-code`** with the challenge and the code marks the address verified and
   finishes the sign-in: the token pair, or the [two-factor challenge](/two-factor) for an account
   with a second factor.
3. **`POST /auth/login`** for an account that has not confirmed yet answers the same challenge, and
   mails a fresh code - but only **after the password is right**. A wrong password is the ordinary
   401, so nobody without the password learns whether an address was ever verified.

```json
{
  "email_verification_required": true,
  "challenge": "q2Vb3...",
  "expires_in": 3600,
  "method": "code",
  "email": "a***@example.com"
}
```

Branch on `email_verification_required`, the way you branch on `two_factor_required`. `method` says
which screen to show - `code` for the default, a six-digit field titled "Confirm your email" - and
`email` is the address it went to, masked, for a "we sent it to" line. `expires_in` is the
challenge's; the code inside it lasts `EmailVerificationCodeLifetime`.

### The endpoints

Both anonymous, rate limited like `/auth/login`, and mapped only with the option on.

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/email/verify-code` | 200 with a token pair, 200 with a two-factor challenge, 400, or 401 |
| POST | `/auth/email/resend-code` | 204, 401, 429, or 502 |

```json
// POST /auth/email/verify-code
{ "challenge": "q2Vb3...", "code": "123456" }

// POST /auth/email/resend-code
{ "challenge": "q2Vb3..." }
```

| Answer | Body | Means |
|---|---|---|
| 400 | `{ "error": "invalid_code", ... }` | Wrong code. Let them type it again |
| 400 | `{ "error": "code_expired", ... }` | No code is outstanding any more - expired, spent, or tried five times. Offer a resend |
| 401 | `{ "error": "invalid_grant", ... }` | The challenge itself is done - expired, spent, the password changed, or the account is locked. Back to sign-in |
| 429 | `{ "errors": ["..."] }` and `Retry-After` | A code went out inside `LocalLogin:MailRequestCooldown`. The one already sent still works |
| 502 | `{ "error": "notification_failed", ... }` | The code could not be sent. Try again |

There is no `rememberDevice` here: a trusted device stands in for a second factor, and none has been
presented yet. An account with one is sent on to `/auth/2fa/verify`, which takes it.

### What the code is

Six digits from a CSPRNG, kept only as an HMAC of the user and the code under a key derived from the
local signing key, so a copy of the table gives none of them up; rotating the signing key retires the
codes in flight. Single use, `EmailVerificationCodeLifetime` (fifteen minutes) long, compared in
constant time, and spent after five wrong tries. Asking for another retires the one before.

Every wrong code also counts toward the account's lockout, exactly as a wrong
[two-factor code](/two-factor#wrong-codes-count-toward-lockout) does: five lock the account, and the
lock grows each time.

Signing in again inside the cooldown hands back a new challenge without mailing another code, and the
code already in the mailbox answers it.

### What confirming writes

The same as redeeming a link: `EmailConfirmedAt`, the profile's `Email`, and the release of the
address from any other account that only typed it in, with the same `email-changed` and
`email-address-released` [audit events](/audit-events). Each code sent publishes
`email-verification-sent`. A redeemed `/auth/email` link satisfies the requirement too.

### Sessions that already exist

Turning the option on also refuses `/auth/refresh` for a session a **password** started, while its
account is unverified: the family is revoked with `email-not-verified`, the client gets the usual 401,
and signing in again offers the challenge. Without that, every unverified account would keep its
sessions for up to `RefreshTokenAbsoluteLifetime` after the switch. Access tokens already issued run
out within `AccessTokenLifetime`.

Sessions from a passkey, an identity provider or a magic link are not touched. None of those went
through a password, and a magic link is only ever sent to an address that is already verified, so a
magic-link sign-in never meets an unverified credential.

### Accounts with no address

A credential with no address cannot be confirmed, so with the option on it cannot sign in with a
password - the answer is the ordinary 401, and the log says why. Registration requires an address,
and `POST /auth/users` refuses to create an account without one. A password added to an
identity-provider account carries no address; add one at `/auth/email`, signed in through the
provider, before using that password.

### Proving the address some other way

The code is the default `IEmailVerificationMethod`. Register your own and the challenge, the
endpoints, lockout and what confirming writes stay the same; only what is sent and how it is checked
change. `Name` comes back as `method`, so a client can show the right screen.

```csharp
internal sealed class SmsCode(YourSmsGateway sms, YourCodeStore codes) : IEmailVerificationMethod
{
    public string Name => "sms";

    public async Task<EmailVerificationIssueResult> IssueAsync(EmailVerificationIssueRequest request, CancellationToken cancellationToken = default)
    {
        if (await codes.SentRecentlyAsync(request.User.Id, cancellationToken) is { } wait)
            return EmailVerificationIssueResult.CoolingDown(wait);

        await sms.SendAsync(request.User, await codes.IssueAsync(request.User.Id, request.Email, cancellationToken), cancellationToken);
        return EmailVerificationIssueResult.Sent;
    }

    public async Task<EmailVerificationProofOutcome> VerifyAsync(EmailVerificationProofRequest request, CancellationToken cancellationToken = default) =>
        await codes.RedeemAsync(request.User.Id, request.Email, request.Proof, cancellationToken);
}

builder.Services.AddScoped<IEmailVerificationMethod, SmsCode>();
```

Every proof is counted toward lockout before `VerifyAsync` is called, so it need not throttle guesses.
It does have to spend a proof that verified, and answer `Exhausted` or `Expired` for one that cannot be
used any more, which tells the client to offer a resend. With a method of your own no
`IEmailVerificationNotifier` is required for this, and the code table goes unused.

### The default email

`IEmailVerificationEmailTemplate.BuildCode` writes it: "Your verification code is 123456", how long it
lasts, and no name, since a registrant chose their own. Implement `BuildCode` in your template to
change the wording.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:EmailVerificationTokenLifetime` | `1.00:00:00` | Single use |
| `LocalLogin:RequireVerifiedEmailForPasswordReset` | `true` | Read the warning above before upgrading |
| `LocalLogin:RequireVerifiedEmailForSignIn` | `false` | Registration and sign-in wait on a confirmed address. [Above](#requiring-a-verified-address-to-sign-in) |
| `LocalLogin:EmailVerificationCodeLifetime` | `00:15:00` | Single use; five wrong tries spend it |
| `LocalLogin:EmailVerificationChallengeLifetime` | `01:00:00` | How long the challenge can be answered or resent from |
| `LocalLogin:MailRequestCooldown` | `00:01:00` | Also the least time between two codes |
| `Email:Smtp:EmailVerificationLinkTemplate` | none | `{token}` is replaced by the raw token. Only the default template reads it |

Expired rows are swept by `AddToamaisutaaTokenCleanup()` along with every other expiring row this
package writes, codes and challenges included. They live in `ToamaisutaaEmailVerificationCodes` and
`ToamaisutaaEmailVerificationChallenges`, added by the `EmailVerificationCodes` migration.
