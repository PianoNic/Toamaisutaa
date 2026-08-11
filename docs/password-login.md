# Local password login

The fallback, for deployments that cannot run an identity provider. Switching it on means becoming
the identity provider - storing credentials, deciding who is who, issuing something the client
presents afterwards. Use OIDC if you can.

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);   // section "LocalLogin"
builder.Services.AddSingleton<IPasswordResetNotifier, YourEmailSender>();

app.MapToamaisutaaPasswordEndpoints();
```

It needs `AddToamaisutaaBearer` as well - the tokens it issues are validated by the same pipeline
that validates your identity provider's, which is why `Toamaisutaa.AspNetCore` depends on
`Toamaisutaa.OpenIdConnect`. A store registration and an `IPasswordResetNotifier` are also required,
and all three are checked at startup rather than at the first request.

## The endpoints

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/login` | 200 with a token pair, 200 with a two-factor challenge, or 401 |
| POST | `/auth/refresh` | 200 with a rotated pair, or 401 |
| POST | `/auth/logout` | 204 |
| POST | `/auth/register` | 201, 400, or 409. Only mapped when `AllowSelfRegistration` is true |
| POST | `/auth/password` | 204. Authenticated. Sets a first password or changes an existing one |
| POST | `/auth/password/forgot` | 204, always |
| POST | `/auth/password/reset` | 204 or 400 |

A successful sign-in returns a short-lived access token and an opaque refresh token. The access
token is signed locally and validated by the same bearer pipeline, so policies, `ICurrentUser` and
provisioning cannot tell the two apart.

A user may have a password, external logins, or both. Adding a password to an account that arrived
through OIDC is supported and touches nothing on the external side.

Once a user enrols in [two-factor authentication](/two-factor), `/auth/login` returns a challenge
instead of tokens and the sign-in finishes at `/auth/2fa/verify`.

## Things to know before switching it on

### Why not just SHA-256?

It is SHA-256. PBKDF2-HMAC-SHA256 is SHA-256 run 600,000 times in a chain, where each round's output
feeds the next, so there is no way to skip to the end.

That chain is the entire feature. A single SHA-256 is built to be fast, and fast is the wrong
property for a password: commodity hardware does billions of SHA-256 operations a second, so a
stolen table of single-round hashes is a dictionary attack that finishes over lunch. Six hundred
thousand rounds makes one guess cost about a tenth of a second. Nobody notices that once at sign-in;
an attacker working through a word list notices it every single time.

The salt handles the other half. Without one, identical passwords produce identical hashes, so
cracking one row cracks every account that shares that password and a precomputed table works
against everybody at once. With one, each row has to be attacked on its own.

#### The rule underneath, which is worth carrying

This codebase uses both. Passwords go through 600,000 rounds of PBKDF2 with a salt; refresh tokens,
password reset tokens and recovery codes are stored as a **plain, unsalted, single-round SHA-256**.
That is not an inconsistency, and the deciding question is always the same one:

**Does the input have entropy of its own?**

- **Passwords do not.** People choose them, from a space small enough to enumerate. The hash has to
  supply the cost that the input does not, which is what iteration buys - and a salt, because
  low-entropy inputs collide across users.
- **Tokens do.** They are 256 bits straight from the system random generator. There is no dictionary
  to try, so iteration defends against nothing; no two can collide, so a salt has nothing to do. All
  that is left is looking one up by exact match on every request, which a fast hash does well and a
  slow one would turn into a per-request cost buying nothing.

So: slow and salted when a human picked it, fast and plain when the random generator did. Reach for
the expensive one by default, and be able to say why when you do not.

### Passwords are hashed with PBKDF2, not Argon2id

PBKDF2-HMAC-SHA256 at 600,000 iterations, from the base class library. This is a dependency
decision, not a cryptographic preference: nothing third-party belongs in the credential path of a
library other people consume, and .NET has no in-box Argon2 - the runtime delegates primitives to
the platform and only OpenSSL implements it, so there is none coming.

State the cost plainly: PBKDF2 is compute-hard, not memory-hard, so it is materially weaker than
Argon2id against an attacker with GPUs. If you want Argon2, register your own `IPasswordHasher`.
Every stored hash names the algorithm and parameters that produced it, so your rows and ours
interoperate and each one is rewritten on the next successful login.

### A pepper is available, and off by default

Set `LocalLogin:Pepper` to a base64 secret of at least 32 bytes and passwords are reduced through
`HMAC-SHA256(pepper, password)` before derivation. Its entire value is that it does not live in the
database, so keep it where the database credentials do not reach.

Rotate by moving the old key into `LocalLogin:RetiredPeppers` under its version marker and setting a
new `Pepper` and `PepperVersion`; rows rewrite themselves as people log in. Lose it with no retired
copy and every password becomes unverifiable.

### Local accounts have no roles

This package has no roles table, so a locally issued token carries no role claims and satisfies no
role requirement, including `Oidc:AdminRole`. Register an `IUserRoleProvider` to supply them from
wherever your roles actually live.

### Lockout is a denial-of-service vector, on purpose

Five failures in fifteen minutes locks an account for fifteen minutes, counted against the account
rather than the caller. Someone who knows a user name can keep that person locked out. The
alternative is an unthrottled online guessing oracle, which is worse. Per-IP rate limiting on the
anonymous endpoints covers the other half, and is enforced by the endpoints themselves rather than
by middleware you have to remember to add.

### Registration reveals whether an account exists

A taken user name answers 409. Hiding that needs an email round trip, and email delivery is
deliberately not in this package. Registration is off by default; turning it on accepts this.

### Password reset delivery is yours

`IPasswordResetNotifier` is required and has no default implementation - startup fails without one.
Requesting a reset always answers 204, for an unknown address and for an account owned by an
identity provider alike. The log says which, and that line is the only way anyone diagnoses "no
email ever arrived".

### Revoking sessions means local sessions

A password change or reset revokes every refresh token this package issued. An access token your
identity provider issued keeps working until it expires, because we cannot revoke it.

### Expired tokens accumulate unless you sweep them

`AddToamaisutaaTokenCleanup()` runs a periodic delete. Without it, plan to call
`IRefreshTokenStore.DeleteExpiredAsync` from your own scheduler.

## Refresh tokens

Stored hashed, never in the clear, and rotated on every use. Presenting a token that has already
been rotated proves two parties hold the chain, so the whole family is revoked and the event is
logged loudly - the standard mitigation for a stolen refresh token.

Rotation alone would keep a session alive forever, so a chain also has an absolute lifetime
(`RefreshTokenAbsoluteLifetime`, 90 days) measured from the sign-in that started it.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:SigningKey` | | Base64, at least 32 bytes. Required. No generated fallback |
| `LocalLogin:Issuer` | `toamaisutaa` | Changing it invalidates every token in flight |
| `LocalLogin:Audience` | `Oidc:ClientId` | |
| `LocalLogin:AccessTokenLifetime` | `00:15:00` | |
| `LocalLogin:RefreshTokenLifetime` | `14.00:00:00` | |
| `LocalLogin:RefreshTokenAbsoluteLifetime` | `90.00:00:00` | How long a rotating chain may live |
| `LocalLogin:Pbkdf2Iterations` | `600000` | Startup floor |
| `LocalLogin:SaltSizeBytes` / `HashSizeBytes` | `16` / `32` | Startup floor |
| `LocalLogin:Pepper` / `PepperVersion` / `RetiredPeppers` | none / `1` / empty | See above |
| `LocalLogin:LockoutEnabled` | `true` | |
| `LocalLogin:MaxFailedAttempts` | `5` | |
| `LocalLogin:LockoutWindow` / `LockoutDuration` | `00:15:00` | |
| `LocalLogin:MinimumPasswordLength` | `8` | NIST: a length floor, no composition rules |
| `LocalLogin:MaximumPasswordLength` | `128` | Not a strength rule - a bound on an anonymous endpoint |
| `LocalLogin:PasswordResetTokenLifetime` | `01:00:00` | Single use |
| `LocalLogin:AllowSelfRegistration` | `false` | When false the endpoint is not mapped at all |
| `LocalLogin:EndpointPrefix` | `/auth` | |
| `LocalLogin:RateLimit:Enabled` | `true` | Per caller address, fixed window |
| `LocalLogin:RateLimit:PermitLimit` / `Window` | `10` / `00:01:00` | |
| `LocalLogin:TokenCleanupInterval` | `06:00:00` | Only used by `AddToamaisutaaTokenCleanup()` |
