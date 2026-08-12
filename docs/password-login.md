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

::: warning Requests are camelCase, token responses are not
Request bodies bind to this package's own records, so they are camelCase: `identifier`,
`refreshToken`, `newPassword`. **Sign-in responses use the RFC 6749 names** - `access_token`,
`refresh_token`, `expires_in`, `token_type` - because a token endpoint is a place where a standard
already exists.

The asymmetry is deliberate and it is the one thing here you cannot guess. Everything else this
package returns is camelCase.
:::

### Bodies

**`POST /auth/login`** - `deviceToken` is optional, and only meaningful with
[trusted devices](/trusted-devices).

```json
{ "identifier": "ada", "password": "correct horse battery staple", "deviceToken": null }
```

Answers **200** with a token pair. `recovery_codes_running_low` is `true` or `null`, never `false`;
`device_token` and `device_expires_in` are null unless a device was trusted.

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M",
  "expires_in": 900,
  "token_type": "Bearer",
  "recovery_codes_running_low": null,
  "device_token": null,
  "device_expires_in": null
}
```

Or **200 with a challenge and no tokens**, for a user who has enrolled in
[two-factor authentication](/two-factor). Branch on `two_factor_required`, which is absent from the
shape above:

```json
{ "two_factor_required": true, "challenge": "No1CXq9-...", "expires_in": 300 }
```

**`POST /auth/refresh`** answers the same token-pair shape, or 401.

```json
{ "refreshToken": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M" }
```

**`POST /auth/logout`** answers 204 whether or not that token existed.

```json
{ "refreshToken": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M" }
```

**`POST /auth/register`** answers **201** with the same token-pair shape, so a registration signs the
user straight in.

```json
{ "userName": "ada", "email": "ada@example.com", "password": "correct horse battery staple" }
```

**`POST /auth/password`** - authenticated. Omit `currentPassword` when the account arrived through an
identity provider and is gaining its first password. Answers 204 or 400.

```json
{ "currentPassword": "the old one", "newPassword": "the new one" }
```

**`POST /auth/password/forgot`** answers 204 always - for an unknown address and for an account an
identity provider owns alike.

```json
{ "email": "ada@example.com" }
```

**`POST /auth/password/reset`** answers 204 or 400.

```json
{ "token": "the token from the notifier", "newPassword": "the new one" }
```

### The two error shapes

**A credential that was not accepted** answers 401 with the RFC 6749 shape. Wrong password, no such
account, locked out and an unknown refresh token are all this one body, because telling them apart
tells a caller which user names are real:

```json
{ "error": "invalid_grant", "error_description": "The credentials are not valid." }
```

**Input the caller can correct** answers 400 - or 409 for a taken user name - with a camelCase array.
These strings are written to be shown to the person who typed the input:

```json
{ "errors": ["Use at least 8 characters."] }
```

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

#### The rule underneath

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

### Where PBKDF2 stops, and how to replace it

PBKDF2 is **compute-hard but not memory-hard**: each guess costs processor time and almost no memory,
which is the shape an attacker with a rack of GPUs is best equipped to parallelise. A memory-hard
function - Argon2id is the usual choice - makes each guess claim real memory too, and that is
materially harder to run thousands of at once. If you are protecting credentials whose loss would be
serious, that difference is worth having.

It is not the default here for a dependency reason rather than a cryptographic one. PBKDF2 is in the
base class library; .NET has no in-box Argon2, and none is coming, because the runtime delegates
primitives to the platform and only OpenSSL implements it. Taking a third-party package into the
credential path of a library other people install is a decision this package will not make on your
behalf.

So it is a seam instead. Register your own `IPasswordHasher` and it wins:

```csharp
builder.Services.AddSingleton<IPasswordHasher, YourArgon2Hasher>();
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

Every stored hash is a PHC string naming the algorithm and parameters that produced it, so existing
rows keep verifying and each one is rewritten under the new scheme on that user's next successful
sign-in. There is no migration to run and no flag day.

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
