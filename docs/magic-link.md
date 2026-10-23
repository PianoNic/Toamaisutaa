# Magic-link sign-in

An emailed link that signs somebody in, for a deployment that wants passwordless without running an
identity provider. Two endpoints, one single-use token, and one rule that shapes everything else:
**a link only ever goes to an address somebody has proven.**

```csharp
builder.Services.AddSingleton<IMagicLinkNotifier, YourEmailSender>();
```

Optional, like `IEmailVerificationNotifier` and unlike `IPasswordResetNotifier`. Registering it is
what maps the two endpoints - neither exists on the wire without it - and it is what makes
`IPasswordAccountService.RequestMagicLinkAsync` work at all; calling it without one throws, at the
call site rather than at startup.

`SendAsync` is called after `POST /auth/magic-link` has answered 204, in a scope of its own, with no
`HttpContext`. Build the link from configuration, not from the request's host: a notifier that reads
the request throws there, and the failure is only logged.

If SMTP is what you want, `Toamaisutaa.Email.Smtp` supplies a notifier:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaSmtpEmailVerification();
builder.Services.AddToamaisutaaSmtpMagicLink();
```

`Email:Smtp:MagicLinkTemplate` is checked at startup, the same as the reset, invitation and
verification links, unless you register your own `IMagicLinkEmailTemplate`.

::: danger This email is the credential
Every other link this package sends leads to a form that asks for something else first - a new
password, a user name. This one is exchanged for a token pair. Anyone who opens it is signed in, so
treat the message the way you would treat a password: never log it, never render it into a shared
inbox view, and keep the page it points at off anything that records query strings.
:::

## The two endpoints

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/magic-link` | 204, always. Anonymous, rate limited. Only mapped when an `IMagicLinkNotifier` is registered |
| POST | `/auth/magic-link/verify` | 200 with a token pair, 200 with a two-factor challenge, or 401. Anonymous, rate limited |

**`POST /auth/magic-link`** - anonymous. Answers 204 for an address nobody holds, for an account an
identity provider owns, and for an address nobody has verified, exactly as it does for a link on its
way. The log says which. As with a reset, the work happens after the response, so the time taken
says nothing either, and `LocalLogin:MailRequestCooldown` drops a second request for one address
inside a minute.

```json
{ "email": "ada@example.com" }
```

**`POST /auth/magic-link/verify`** - anonymous, because the link is opened from a mailbox and often
on another device. The token is what proves anything here.

```json
{ "token": "the token from the notifier" }
```

It answers [the same two shapes `/auth/login` does](/password-login#bodies), so a client that already
handles a password sign-in handles this one too.

## The verified-address rule

A magic link is issued only when `ToamaisutaaPasswordCredentials.EmailConfirmedAt` is set. That is
not an option and does not have one: unlike a reset link, a magic link mailed to the wrong address
*is the account*, with nothing else asked for.

So a freshly registered account cannot use a magic link until its address is verified at
[`/auth/email`](/email-verification#asking-for-the-link-again). Startup refuses the one configuration
where that could never happen: an `IMagicLinkNotifier` registered with no `IEmailVerificationNotifier`
beside it, where no address could ever qualify and the endpoint would answer 204 forever while
sending nothing.

## `amr` says `email`, not `pwd`

A token from a magic link carries `email` in `amr`. It does not carry `pwd`, because no password was
typed, so `RequireClaim("amr", "pwd")` fails for a magic-link session. The claim is carried on the
refresh family rather than recomputed, so a session that signed in with a link still reports `email`
a week later.

## Two-factor still applies

An account with a confirmed second factor is challenged: `/auth/magic-link/verify` answers with the
challenge shape, and the code goes to `/auth/2fa/verify`, the same endpoint a password sign-in uses.
The finished token says `email otp mfa`.

**A trusted device does not skip that challenge here**, unlike at `/auth/login`. There the cached
factor sits behind a password; here it would sit behind a mailbox alone, and two cached things are
not two factors.

**The link is spent on the way to the challenge**, whether or not the challenge is finished.

## Lifetimes and sweeping

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:MagicLinkTokenLifetime` | `00:15:00` | Single use. Shorter than the reset link on purpose |
| `Email:Smtp:MagicLinkTemplate` | none | `{token}` is replaced by the raw token. Only the default template reads it |

The default email says how long the link has, and reads the number from this setting rather than
from one of its own.

Asking for a second link retires the first, so a mailbox never holds two that work. Expired rows are
swept by `AddToamaisutaaTokenCleanup()` along with every other expiring row this package writes.
