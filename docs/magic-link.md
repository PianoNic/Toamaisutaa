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
way. The log says which.

```json
{ "email": "ada@example.com" }
```

**`POST /auth/magic-link/verify`** - anonymous, because the link is opened from a mailbox and often
on another device. The token is what proves anything here.

```json
{ "token": "the token from the notifier" }
```

It answers the same body `/auth/login` does - `access_token`, `refresh_token`, `expires_in`,
`token_type` - so a client that already handles a password sign-in handles this one too.

## The verified-address rule

A magic link is issued only when `ToamaisutaaPasswordCredentials.EmailConfirmedAt` is set. That is
not an option and does not have one.

The reason is the difference between this and a reset link. A reset link mailed to a typo'd address,
or to one somebody else now owns, lets whoever reads it set a password - which is bad, and which is
why `RequireVerifiedEmailForPasswordReset` exists as a choice. A magic link mailed to the same
address *is the account*, immediately, with nothing else asked for. There is no version of that worth
offering as a setting.

So a freshly registered account cannot use a magic link until its address is verified at
[`/auth/email`](/email-verification#asking-for-the-link-again). Startup refuses the one configuration
where that could never happen: an `IMagicLinkNotifier` registered with no `IEmailVerificationNotifier`
beside it, where no address could ever qualify and the endpoint would answer 204 forever while
sending nothing.

## `amr` says `email`, not `pwd`

A token from a magic link carries `email` in `amr`. It does not carry `pwd`, because no password was
typed.

That matters for policies. `RequireClaim("amr", "pwd")` fails for a magic-link session, and it
should: whatever that policy is protecting, it asked for a password. The claim survives a refresh -
it is carried on the refresh family rather than recomputed - so a session that signed in with a link
still reports `email` a week later.

`email` is not one of the RFC 8176 values; the registry has nothing for possession of a mailbox. It
is spelled the way identity providers offering emailed sign-in already spell it, and left unprefixed
for that reason, unlike the `toa_` claims this package invents.

## Two-factor still applies

An account with a confirmed second factor is challenged. `/auth/magic-link/verify` answers the same
second success shape `/auth/login` does:

```json
{ "two_factor_required": true, "challenge": "No1CXq9-...", "expires_in": 300 }
```

Present it with a code to `/auth/2fa/verify`, the same endpoint a password sign-in uses. The finished
token says `email otp mfa`.

**A trusted device does not skip that challenge here**, unlike at `/auth/login`. There the cached
factor sits behind a password; here it would sit behind a mailbox alone, and two cached things are
not two factors.

**The link is spent on the way to the challenge**, whether or not the challenge is finished. It got
the account holder as far as the second factor, which is all a first factor ever does - and the
alternative leaves a live credential sitting in a mailbox that has already been read once.

## Lifetimes and sweeping

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:MagicLinkTokenLifetime` | `00:15:00` | Single use. Shorter than the reset link on purpose |
| `Email:Smtp:MagicLinkTemplate` | none | `{token}` is replaced by the raw token. Only the default template reads it |

Fifteen minutes is the one lifetime in this package that was argued *down*. A reset link is a step
towards a session and can afford an hour; this one is the session, so the window in which a
forwarded or archived message still works is kept short. The default email says how long it has, and
reads the number from this setting rather than from one of its own.

Asking for a second link retires the first, so a mailbox never holds two that work. Expired rows are
swept by `AddToamaisutaaTokenCleanup()` along with every other expiring row this package writes.
