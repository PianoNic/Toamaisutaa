# Toamaisutaa

**トアマイスター** / Toamaisutaa / "gate master" - German *Tormeister* run through katakana and back
out again.

Authentication for ASP.NET Core, packaged: OIDC token validation, claims mapping, optional user
provisioning, and its own EF Core migrations.

Two ways in:

- **OIDC bearer validation.** The recommended path. The authorization-code flow with PKCE runs in
  your client; Toamaisutaa validates what it sends and gives you a local user if you want one.
- **Local username and password login.** The fallback, for deployments that cannot run an identity
  provider. You become the identity provider, with everything that implies.

Use OIDC if you can. Local login exists because not every deployment can, and it is built to be
conservative rather than convenient.

Server-side interactive sign-in and two-factor authentication are later phases and are deliberately
absent rather than stubbed.

## Packages

| Package | Contains |
|---|---|
| `Toamaisutaa.Abstractions` | interfaces, options, DTOs. No dependencies at all |
| `Toamaisutaa.Core` | claims mapping, the provisioning decision, linking rules. No ASP.NET, no EF |
| `Toamaisutaa.OpenIdConnect` | `AddToamaisutaaBearer`, JWT validation, userinfo enrichment |
| `Toamaisutaa.AspNetCore` | authorization, `ICurrentUser`, the SPA configuration endpoint |
| `Toamaisutaa.EntityFrameworkCore` | entities, configurations, stores, `ToamaisutaaDbContext` |
| | tables: users, external logins, password credentials, refresh tokens, reset tokens |
| `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` | the Postgres migration set |
| `Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite` | the SQLite migration set |

`Core` and `Abstractions` run anywhere, including a worker service or a console app with no ASP.NET
in sight.

## Minimum

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
app.MapToamaisutaaConfiguration();   // GET /api/app, for the SPA to read at startup
```

That authenticates every endpoint by default and needs no database. Three of the four applications
this was extracted from want nothing more than that.

## With a local user

```csharp
builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
builder.Services.AddToamaisutaaCurrentUser();
```

Then inject `ICurrentUser`:

```csharp
var user = await currentUser.GetOrProvisionAsync(cancellationToken);
```

The row is created on the first request that ever carries this subject, and after that it is read,
not rewritten. `ProfileSyncMode` decides when a claim change is written back; the default,
`OnChange`, writes only when something actually differs.

Prefer your own `DbContext`? Call `modelBuilder.ApplyToamaisutaaConfiguration()` in its
`OnModelCreating`, register `AddToamaisutaaEntityFrameworkStores<YourContext>()`, and generate the
migration in your own project - the two migration packages above only carry
`ToamaisutaaDbContext`.

## Configuration

Everything binds from the `Oidc` section.

| Key | Default | Notes |
|---|---|---|
| `Oidc:Authority` | | The issuer as your tokens see it |
| `Oidc:InternalAuthority` | `Authority` | Where this process reaches the issuer for discovery, when that differs |
| `Oidc:ClientId` | | Also the default valid audience |
| `Oidc:RequireHttpsMetadata` | `true` | |
| `Oidc:ValidateIssuer` | `true` | |
| `Oidc:ValidateAudience` | `true` | |
| `Oidc:ValidAudiences:0` | `[ClientId]` | |
| `Oidc:NameClaim` | `name` | |
| `Oidc:RoleClaim` | `roles` | Set to `groups` for Pocket ID, Authentik and Entra |
| `Oidc:FetchClaimsFromUserInfo` | `true` | Reads roles from userinfo when the access token omits them |
| `Oidc:UserInfoCacheDuration` | `00:05:00` | Cached per subject |
| `Oidc:Scope` | `openid profile email roles` | Served to the client |
| `Oidc:RedirectUri` | derived | Falls back to `PublicUrl`, then the request origin |
| `Oidc:PostLogoutRedirectUri` | `RedirectUri` | |
| `Oidc:PublicUrl` | | Used to derive the two above |
| `Oidc:AdminRole` | | Registers the `Toamaisutaa.Admin` policy when set |
| `Oidc:RequireAdminRoleGlobally` | `false` | Puts the admin role in the fallback policy |
| `Oidc:QueryToken:IncludePaths:0` | | Path prefixes where `?access_token=` is honoured, for SignalR |
| `Oidc:QueryToken:ExcludePaths:0` | | Carved back out of the above |

No endpoint is ever constructed by hand: authorization, token and userinfo URLs all come from the
issuer's discovery document, so Authentik, Keycloak, Pocket ID, Okta and Entra are a configuration
change rather than a code change.

## Local password login

Opt in, on top of `AddToamaisutaaBearer`:

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);   // section "LocalLogin"
builder.Services.AddSingleton<IPasswordResetNotifier, YourEmailSender>();

app.UseRateLimiter();                     // required, see below
app.MapToamaisutaaPasswordEndpoints();
```

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/login` | 200 with a token pair, or 401 |
| POST | `/auth/refresh` | 200 with a rotated pair, or 401 |
| POST | `/auth/logout` | 204 |
| POST | `/auth/register` | 201, 400, or 409. Only mapped when `AllowSelfRegistration` is true |
| POST | `/auth/password` | 204. Authenticated. Sets a first password or changes an existing one |
| POST | `/auth/password/forgot` | 204, always |
| POST | `/auth/password/reset` | 204 or 400 |

A successful sign-in returns a short-lived access token and an opaque refresh token. The access
token is signed locally and validated by the same bearer pipeline that validates your identity
provider's, so policies, `ICurrentUser` and provisioning cannot tell the two apart. Refresh tokens
are stored hashed, rotate on every use, and are revoked as a family if a rotated one is ever
presented again.

A user may have a password, external logins, or both. Adding a password to an account that arrived
through OIDC is supported and does not touch the external side.

### Things you should know before switching this on

**Passwords are hashed with PBKDF2, not Argon2id.** PBKDF2-HMAC-SHA256 at 600,000 iterations, from
the base class library. This is a dependency decision, not a cryptographic preference: nothing
third-party belongs in the credential path of a library other people consume, and .NET has no in-box
Argon2 - the runtime delegates primitives to the platform and only OpenSSL implements it, so there
is none coming. The cost is real and worth stating plainly: PBKDF2 is compute-hard, not memory-hard,
so it is materially weaker than Argon2id against an attacker with GPUs. If you want Argon2, register
your own `IPasswordHasher`. Every stored hash names the algorithm and parameters that produced it,
so your rows and ours interoperate and each one is rewritten on the next successful login.

**A pepper is available and off by default.** Set `LocalLogin:Pepper` to a base64 secret of at least
32 bytes and passwords are reduced through `HMAC-SHA256(pepper, password)` before derivation. Its
entire value is that it does not live in the database, so keep it somewhere the database credentials
do not reach. Rotate by moving the old key into `LocalLogin:RetiredPeppers` under its version marker
and setting a new `Pepper` and `PepperVersion`; rows rewrite themselves as people log in. Lose it
with no retired copy and every password becomes unverifiable.

**Local accounts have no roles.** This package has no roles table, so a locally issued token carries
no role claims and satisfies no role requirement, including `Oidc:AdminRole`. Register an
`IUserRoleProvider` to supply them from wherever your roles actually live.

**Lockout is a denial-of-service vector, on purpose.** Five failures in fifteen minutes locks an
account for fifteen minutes, counted against the account rather than the caller. That means someone
who knows a user name can keep that person locked out. The alternative is an unthrottled online
guessing oracle, which is worse. Per-IP rate limiting on the anonymous endpoints covers the other
half.

**Rate limiting needs `app.UseRateLimiter()`.** The endpoints carry the policy, but without the
middleware in the pipeline that metadata does nothing and the anonymous endpoints are unthrottled.

**Registration reveals whether an account exists.** A taken user name answers 409. Hiding that needs
an email round trip, and email delivery is deliberately not in this package. Registration is off by
default; when you turn it on, this is part of the deal.

**Password reset delivery is yours.** `IPasswordResetNotifier` is required and has no default
implementation - startup fails without one. Requesting a reset always answers 204, for an unknown
address and for an account owned by an identity provider alike; the log says which, and that log
line is the only way anyone diagnoses "no email ever arrived".

**Revoking sessions means local sessions.** A password change or reset revokes every refresh token
this package issued. An access token your identity provider issued keeps working until it expires,
because we cannot revoke it.

**Expired tokens accumulate unless you sweep them.** `AddToamaisutaaTokenCleanup()` runs a periodic
delete; without it, plan to run `IRefreshTokenStore.DeleteExpiredAsync` from your own scheduler.

### Local login configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:SigningKey` | | Base64, at least 32 bytes. Required. No generated fallback |
| `LocalLogin:Issuer` | `toamaisutaa` | Changing it invalidates every token in flight |
| `LocalLogin:Audience` | `Oidc:ClientId` | |
| `LocalLogin:AccessTokenLifetime` | `00:15:00` | |
| `LocalLogin:RefreshTokenLifetime` | `14.00:00:00` | |
| `LocalLogin:RefreshTokenAbsoluteLifetime` | `90.00:00:00` | How long a rotating chain may live before re-authentication |
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

## Notes for existing deployments

- **`MapInboundClaims` is off and not configurable.** Claim types stay as the issuer wrote them
  (`sub`, `preferred_username`, `roles`). If your current setup leaves inbound mapping on while
  naming raw claims in `NameClaimType`/`RoleClaimType`, those two settings have been fighting each
  other and this fixes it - but check anything that reads `ClaimTypes.*` directly.
- **Audience validation is on by default.** If your tokens' `aud` does not name your API, set
  `Oidc:ValidAudiences` or turn `Oidc:ValidateAudience` off deliberately.
- **There is no development bypass.** Nothing in these packages authenticates an unauthenticated
  request. Run a mock issuer instead; `samples/MinimalApiSample` shows one in four lines of Docker.

## Sample

`samples/MinimalApiSample` runs the whole thing against a throwaway issuer: anonymous endpoint,
provisioning endpoint, admin-only endpoint, and the client configuration endpoint.

## Licence

PolyForm. See `LICENSE.md`.
