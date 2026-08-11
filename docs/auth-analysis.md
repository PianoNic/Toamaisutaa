# Auth analysis: gaggaotaku, CommandBlock, HOPPER, KRINT

Written 2026-08-11 as input for Toamaisutaa. Sources are the four working trees at
`C:\Coding\{gaggaotaku,CommandBlock,HOPPER,KRINT}` as they stand today. Line references are to
those files.

**The single most important finding up front:** none of the four codebases runs an OIDC flow on
the server. All four are pure JWT-bearer resource servers; the authorization-code + PKCE flow
runs in the browser (`oidc-client-ts` in one, `angular-auth-oidc-client` in three). Nothing in
these four repos uses `AddOpenIdConnect`, cookie authentication, `SignInAsync`, or a server-side
session. That contradicts the Phase 2 brief, which describes wiring on top of
`Microsoft.AspNetCore.Authentication.OpenIdConnect`. See "Open questions", Q1.

---

## Gaggaotaku

### 1. Flows that exist

- **Primary:** OIDC authorization code + PKCE, executed entirely in the SPA.
  `src/Gaggaotaku.Frontend/src/main.tsx:87-107` builds an `oidc-client-ts` config with
  `response_type: 'code'` and `automaticSilentRenew: true`; PKCE is implicit (oidc-client-ts
  always sends S256 for code flow). The API is a bearer resource server only
  (`Extensions/AuthenticationExtensions.cs:29-73`).
- **Provider:** PocketID (`.env.example`: "OIDC via your external PocketID instance", issuer is
  the base URL). But `OpenApi/OAuth2SecuritySchemeTransformer.cs:43-44` hardcodes Keycloak's
  `/protocol/openid-connect/auth` and `/token` paths, so the Scalar "Authorize" button is wired
  for the wrong IdP.
- **Second OAuth2 client:** MyAnimeList account linking, server-side authorization code with
  PKCE `plain` (MAL supports nothing else), `Infrastructure/Services/MalService.cs:38-98`.
- **Two non-OIDC surfaces:**
  - `Auth/ExternalApiKeyAttribute.cs` - shared key in `X-Api-Key` or `Authorization: Bearer`,
    constant-time compare, 503 when unconfigured.
  - `Auth/WebDisplayAuth.cs` - one shared password (`WebDisplay:Password`) exchanged for a
    DataProtection time-limited cookie (`wd_auth`, 30 days, `Path=/api/webdisplay`), because the
    consuming embedded browser cannot run a redirect flow.
- **Dev bypass:** `Auth/MockAuthenticationHandler.cs` authenticates every request as a fixed user
  when `Oidc:Mock=true`; the SPA has a matching `MOCK_AUTH` object (`main.tsx:50-68`).

### 2. Token and session handling

Bearer only. No cookie auth for the app itself, no server session store, nothing persisted
server-side about a login. The SPA holds the tokens and silently renews them.
SignalR cannot set headers, so the token arrives as `?access_token=` and is picked up only for
`/hubs` paths (`AuthenticationExtensions.cs:58-72`).

The only server-stored tokens are MyAnimeList's: `User.MalAccessToken`, `MalRefreshToken`,
`MalTokenExpiresAt`, **stored in plaintext**. Refresh is lazy and transparent, triggered by
`EnsureAccessTokenAsync` before each MAL call with a 1-minute skew
(`MalService.cs:238-269`). MAL lifetimes: access 1 h, refresh 1 month.

### 3. Claims handling

`MapInboundClaims = false`, so claim types are the raw JWT names. `NameClaimType = "name"`,
`RoleClaimType = "roles"`, `ValidateAudience = false`, `ValidIssuer` = the public authority while
`MetadataAddress` may point at an internal one. No claims transformation, no enrichment.
Roles are requested in scope and configured as a claim type, but **no role is ever checked**:
the fallback policy is `RequireAuthenticatedUser()` only (`AuthenticationExtensions.cs:78-89`).

### 4. User provisioning

The only one of the four that provisions. `Infrastructure/Services/CurrentUserService.cs:27-53`:
look up `Users` by `Subject`, insert if missing, then overwrite `Email`, `Username`,
`DisplayName`, `AvatarUrl` from the current principal and `SaveChangesAsync()` - **on every
call**, whether anything changed or not. Linking is by subject ID only. Email is never used for
matching, there is no external-login table, no provider discriminator, and no collision handling
of any kind.

### 5. Data model

One auth-adjacent table, `Users` (`Domain/User.cs`):

| Column | Type | Notes |
|---|---|---|
| `Subject` | string, required | OIDC `sub`, **unique index** |
| `Username` | string? | from `preferred_username` |
| `Email` | string? | from `email` |
| `DisplayName` | string? | from `name`, falls back to `preferred_username` |
| `AvatarUrl` | string? | from `picture` |
| `PrefAutoPlay` / `PrefAutoNext` / `PrefAutoSkip` | bool | player prefs |
| `MalUsername`, `MalUserId`, `MalAccessToken`, `MalRefreshToken`, `MalTokenExpiresAt` | mixed | linked MAL account, plaintext tokens |

`DBConfigurations/UserConfiguration.cs` is three lines: `HasIndex(u => u.Subject).IsUnique()` and
`Property(u => u.Subject).IsRequired()`. No max lengths, no index on email.

### 6. 2FA

None.

### 7. DI and configuration surface

```csharp
services.AddAnimeAuthentication(builder.Configuration);
services.AddAnimeAuthorization();
```

Keys: `Oidc:Mock`, `Oidc:Authority`, `Oidc:InternalAuthority`, `Oidc:RequireHttpsMetadata`,
`Oidc:ClientId`, `Oidc:Scope`, `Oidc:RedirectUri`, `Oidc:PostLogoutRedirectUri`;
`ExternalApi:Key`, `ExternalApi:PublicBaseUrl`, `WebDisplay:Password`,
`Streaming:ProxyTokenKey`, `Mal:ClientId`, `Mal:ClientSecret`, `Mal:RedirectUri`,
`Cors:AllowedOrigins`. `GET /api/app` (`Application/Queries/App/GetAppConfigQuery.cs`) serves the
OIDC config to the SPA at runtime so the frontend build is environment-agnostic.

### 8. What is wrong with it

- **Write amplification and a first-login race.** `GetOrCreateCurrentUserAsync` issues a
  `SaveChangesAsync` on every authenticated request. Two concurrent first requests both insert,
  and the unique index on `Subject` turns the loser into an unhandled `DbUpdateException`.
- **Plaintext third-party refresh tokens** in the database, in a codebase that elsewhere
  demonstrates AES-GCM (`StreamProxyToken`). A DB dump hands over every linked MAL account.
- **`ValidateAudience = false`.** Any token the issuer minted for any client is accepted.
- **The mock handler ships in the production assembly** and authenticates *every* request when a
  single config value flips. One stray `Oidc__Mock=true` is a full auth bypass.
- **OpenAPI transformer hardcodes Keycloak URLs** while the documented IdP is PocketID.
- `roles` requested, `RoleClaimType` set, no authorization ever uses them: dead configuration
  that reads as if authorization exists.
- `AccountController` is `[AllowAnonymous]` and relies on the query checking `IsAuthenticated`
  internally. It happens to be correct, but the guard lives far from the attribute.

---

## CommandBlock

### 1. Flows that exist

OIDC authorization code + PKCE in the browser only, via `angular-auth-oidc-client`
(`src/CommandBlock.Frontend/src/app/shared/auth/auth.config.ts`: `responseType: 'code'`,
`silentRenew: true`, `useRefreshToken: true`). The IdP is a **self-hosted Keycloak realm shipped
in the repo** (`keycloak/commandblock-realm.json`): public client, `standardFlowEnabled: true`,
`implicitFlowEnabled: false`, `directAccessGrantsEnabled: false`,
`pkce.code.challenge.method: S256`. Login/registration/2FA UI is a Keycloakify theme
(`keycloak/keycloakify/`) covering login, OTP, recovery codes, WebAuthn, password reset. No local
password login in the app, no machine-token scheme.

### 2. Token and session handling

Bearer only, no cookies, no server session store. Refresh token held by the browser, renewed 30 s
before expiry. Realm lifetimes: access token 300 s, SSO idle 1800 s, SSO max 36000 s, offline
session idle 2592000 s (30 days). SignalR reads `?access_token=` for `/hubs`
(`API/Program.cs:99-110`).

### 3. Claims handling

`API/Program.cs:83-111`. `NameClaimType = "name"`, `RoleClaimType = "roles"`,
`ValidateAudience = false`, `ValidIssuer` = public authority, `MetadataAddress` from the internal
authority, and `ValidateIssuer` is **configurable and switched off in Development**
(`Oidc:ValidateIssuer`, for gul tunnel URLs). **`MapInboundClaims` is not disabled here**, unlike
gaggaotaku and HOPPER, while the claim types are configured as if raw JWT names arrive. Realm
roles `user` and `admin` exist and are never enforced; the fallback policy is
`RequireAuthenticatedUser()`.

### 4. User provisioning

None. There is no user table. The only trace of a human is a denormalized actor string on
`ActivityEntry`, filled by `HttpCurrentUserService.GetActorName()` from
`preferred_username ?? name ?? email`.

### 5. Data model

No auth tables. There is, however, **dead auth schema**: migrations create a `Nodes` table with
`TokenHash` and `IsConfigManaged`
(`Infrastructure/Migrations/20260627133802_AddNodeTokenAndConfigManaged.cs`,
`20260701102734_MinecraftCleanupAndWorldBackups.cs:139`) while `CommandBlockDbContext` has no
`Nodes` DbSet and no entity references `TokenHash`. The migration is byte-identical to KRINT's,
same class name, same timestamp: copied wholesale and never cleaned up.

### 6. 2FA

Fully delegated to Keycloak. Realm OTP policy: `totp`, `HmacSHA1`, 6 digits, 30 s period.
Keycloakify supplies the `login-otp`, `login-config-totp`, `login-recovery-authn-code-*` and
`webauthn-*` pages. Nothing in the application.

### 7. DI and configuration surface

No extension method; the whole block is inline in `Program.cs`. Keys: `Oidc:Authority`,
`Oidc:InternalAuthority`, `Oidc:RequireHttpsMetadata`, `Oidc:ValidateIssuer`, `Oidc:ClientId`,
`Oidc:Scope`, `Oidc:RedirectUri`, `Oidc:PostLogoutRedirectUri`, `CommandBlock:PublicUrl`,
`Cors:AllowedOrigins`, `Database:Provider`, `ConnectionStrings:CommandBlockDatabase`.
`GET /api/app` (`Application/Queries/App/AppQuery.cs`) serves the SPA its OIDC config and derives
the redirect URI from `PublicUrl` when unset.

### 8. What is wrong with it

- **`MapInboundClaims` left on** while `NameClaimType`/`RoleClaimType` are set to raw JWT names.
  The two settings fight each other; `User.Identity.Name` and role checks do not behave the way
  the configuration suggests. This is drift from the sibling projects, not a decision.
- **`Oidc:ValidateIssuer` is a config switch that disables issuer validation.** It is defensible
  for the tunnel case and it is documented, but it is a one-line production footgun with a
  friendly name.
- `ValidateAudience = false` as everywhere else.
- **Auth is wired inline in `Program.cs`**, so nothing about it is testable or reusable, while
  HOPPER (same author, same architecture) has it behind an extension method with tests.
- **Dead `Nodes`/`TokenHash` schema** shipped to every deployment.
- `e2e/mock-oauth2-config.json` is the third copy of the same file (see KRINT and HOPPER).

---

## HOPPER

### 1. Flows that exist

- OIDC authorization code + PKCE in the browser (`angular-auth-oidc-client`,
  `src/HOPPER.Frontend/src/app/shared/auth/auth.config.ts`). Deliberately provider-agnostic: the
  `.env.example` and code comments name Pocket ID, Authentik, Keycloak, Okta and Entra.
- **A second first-class authentication scheme**, `ClientToken`
  (`API/Auth/ClientTokenAuthenticationHandler.cs`): a per-server pre-shared bearer token used by
  the game clients. Selected per controller with
  `[Authorize(AuthenticationSchemes = ClientTokenDefaults.AuthenticationScheme)]`.
- Dev/demo auth uses a **mock OAuth2 server container** (`oidc/mock-oauth2-config.json`,
  `interactiveLogin: false`) rather than an in-process bypass handler.
- No local password login.

### 2. Token and session handling

Bearer + opaque client tokens. No cookies, no session store. Browser refreshes 30 s before
expiry. Client tokens are 32 random bytes as lowercase hex (`Application/ServerTokenGenerator.cs`),
stored in `Servers.Token` **in plaintext**, valid until rotated
(`Application/Command/Servers/RotateServerTokenCommand.cs`). Userinfo lookups are cached 5 minutes
in `IMemoryCache`.

### 3. Claims handling

The best of the four (`API/Extensions/AuthExtensions.cs`, `API/Auth/UserInfoClaims.cs`):

- `MapInboundClaims = false`, `NameClaimType = "name"`.
- `RoleClaimType` is **configurable** (`Oidc:RoleClaim`, default `roles`) because Pocket ID,
  Authentik and Keycloak publish membership as `groups`.
- `ValidateAudience` defaults to **true**, with `Oidc:ValidAudiences` falling back to
  `[Oidc:ClientId]`.
- **Claims enrichment:** `UserInfoClaims.Merge` runs on `OnTokenValidated`; when the role claim is
  missing from the access token it calls the issuer's userinfo endpoint (discovered from
  metadata), flattens the JSON into claims (arrays become one claim per entry, which is what makes
  `IsInRole` match a single group), and merges them. Failures degrade to the token's own claims
  rather than 500.
- `OnForbidden` logs which claim was read, what the token carried, and which claim types exist -
  the one place in the four repos where a 403 explains itself.

### 4. User provisioning

None. No user table. `HttpCurrentUserService.Name` returns
`preferred_username ?? ClaimTypes.Name ?? ClaimTypes.Email` for audit strings.

### 5. Data model

No user, external-login, session or 2FA tables. The only auth column is on `Servers`
(`Infrastructure/DBConfigurations/ServerConfiguration.cs`):

```csharp
builder.Property(s => s.Token).HasMaxLength(200);
builder.HasIndex(s => s.Token).IsUnique();
```

### 6. 2FA

None. Entirely the IdP's problem.

### 7. DI and configuration surface

```csharp
services.AddHopperAuthentication(configuration);   // AddJwtBearer(...).AddClientToken()
services.AddHopperAuthorization(configuration);    // FallbackPolicy = authenticated + admin role
```

Keys: `Oidc:Authority`, `Oidc:InternalAuthority`, `Oidc:ClientId`, `Oidc:RedirectUri`,
`Oidc:PostLogoutRedirectUri`, `Oidc:Scope`, `Oidc:RequireHttpsMetadata`, `Oidc:AdminRole`
(default `hopper-admin`), `Oidc:RoleClaim` (default `roles`), `Oidc:FetchClaimsFromUserInfo`
(default true), `Oidc:ValidAudiences[]`, `Oidc:ValidateAudience`, plus `Hopper:*` application
keys. `GET /api/app` serves the SPA config.

It is also the only one of the four with real auth tests: `HOPPER.Tests/Api/AdminAuthorizationTests.cs`,
`AuthSplitTests.cs`, `UserInfoClaimsTests.cs`.

### 8. What is wrong with it

- **Client tokens are stored in plaintext and matched by table scan.**
  `ClientTokenAuthenticationHandler` loads `(Id, Token)` for **every server on every request**, then
  compares each in constant time. It is O(rows) DB reads per request with no cache, and a database
  dump is a full client compromise. KRINT, the sibling project, hashes the equivalent secret. Two
  projects, opposite answers to the same question.
- **The userinfo cache key is `$"userinfo:{token.GetHashCode()}"`.** A 32-bit, non-cryptographic,
  per-process-randomized hash as a cache key for a security-relevant claim set. A collision serves
  one user another user's roles. It should key on a SHA-256 of the token.
- `Hopper__BootstrapClientToken` is documented in `.env.example` and read by no code anywhere in
  the repo. Dead configuration.
- No local user identity at all, so nothing per-user can ever be stored without adding the whole
  concept later.

---

## KRINT

### 1. Flows that exist

- OIDC authorization code + PKCE in the browser. `auth.config.ts` is **byte-identical to
  CommandBlock's**. IdP is a Keycloak realm shipped in the repo (`keycloak/`).
- **Node pre-shared tokens** over SignalR: `/hubs/node` is `[AllowAnonymous]` and authenticates
  inside `OnConnectedAsync` (`API/Hubs/NodeHub.cs:28-63`) by SHA-256-hashing the query-string
  token and matching `Nodes.TokenHash`, with a **legacy plaintext allow-list** fallback
  (`Node:Tokens` in configuration).
- `InnerUser*` (`Application/Command/InnerUser/*`, `Infrastructure/Services/{Postgres,MySql,Mongo}InnerUserService.cs`)
  creates and resets users *inside managed database instances*. Not application authentication;
  mentioned only so it is not mistaken for it.
- No local password login for the app.

### 2. Token and session handling

Bearer for humans, opaque tokens for nodes. No cookies, no session store. `Program.cs:103-118`
pulls `?access_token=` for `/hubs` but **explicitly excludes `/hubs/node`**, since that token is
not a JWT.

KRINT is the only one with an at-rest encryption story: `Infrastructure/Services/SecretsVaultService.cs`
does AES-256-GCM against a `Vault:MasterKey` (base64, validated to exactly 32 bytes, hard failure
if absent or malformed) and stores `(Ciphertext, Nonce, Tag)` per named secret.

### 3. Claims handling

`Program.cs:91-119`: `NameClaimType = "name"`, `RoleClaimType = "roles"`,
`ValidateAudience = false`, `ValidIssuer` = public authority. **`MapInboundClaims` not disabled**,
same as CommandBlock. No enrichment. Roles never enforced.

### 4. User provisioning

None. No app user table. `HttpCurrentUserService.GetActorName()` is byte-identical to
CommandBlock's, doc comment included.

### 5. Data model

No user/external-login/2FA tables. Auth-adjacent:

| Table | Columns | Notes |
|---|---|---|
| `Nodes` | `TokenHash` (text, null), `IsConfigManaged` (bool) | SHA-256 base64 of the node token; lookup by exact hash match |
| `Secrets` | `Name`, `Ciphertext` (blob), `Nonce` (blob), `Tag` (blob) | AES-256-GCM envelope |

**Migrations are split by provider**, which is the precedent Toamaisutaa needs:
`KRINT.Infrastructure` holds the Postgres set, `KRINT.Infrastructure.Migrations.Sqlite` holds the
SQLite set, selected in `Infrastructure/Extensions/DatabaseExtensions.cs` via
`sqlite => sqlite.MigrationsAssembly(SqliteMigrationsAssembly)`. The comment there states the
constraint plainly: "EF Core cannot hold two providers' migration sets and model snapshots in a
single assembly." Provider comes from `Database:Provider`, inferred from the connection string
when unset.

### 6. 2FA

None in the app; the Keycloak realm handles it.

### 7. DI and configuration surface

Inline in `Program.cs`, no extension method. Keys: `Oidc:Authority`, `Oidc:InternalAuthority`,
`Oidc:RequireHttpsMetadata`, `Oidc:ClientId`, `Oidc:Scope`, `Oidc:RedirectUri`,
`Oidc:PostLogoutRedirectUri`, `Krint:PublicUrl`, `Node:Tokens[]`, `Vault:MasterKey`,
`Database:Provider`, `ConnectionStrings:KrintDatabase`, `Cors:AllowedOrigins`.

### 8. What is wrong with it

- **`NodeHub` is `[AllowAnonymous]` and rolls its own authentication** in `OnConnectedAsync`.
  The check lives outside the authentication stack, so no policy, no test harness, and no
  `[Authorize]` covers it. HOPPER solved the same problem properly with an
  `AuthenticationHandler`; KRINT did not.
- **The legacy allow-list compares with `allowed.Contains(token, StringComparer.Ordinal)`** - not
  constant time, and those tokens sit in plaintext configuration.
- Node tokens travel in the **query string**, where proxies and access logs record them.
- `MapInboundClaims` left on, `ValidateAudience = false`, roles never enforced: same drift as
  CommandBlock.
- `SHA256` unsalted is fine for high-entropy tokens (the code says so and is right), but the same
  reasoning was not applied to HOPPER, and neither project knows what the other decided.

---

## Comparison table

| | gaggaotaku | CommandBlock | HOPPER | KRINT |
|---|---|---|---|---|
| Where the code flow runs | Browser | Browser | Browser | Browser |
| Client library | oidc-client-ts / react-oidc-context | angular-auth-oidc-client | angular-auth-oidc-client | angular-auth-oidc-client |
| PKCE | Yes (implicit in lib) | Yes (S256, realm-enforced) | Yes | Yes |
| IdP | PocketID | Keycloak (realm in repo) | Any (Pocket ID / Authentik / Keycloak / Okta / Entra) | Keycloak (realm in repo) |
| Server-side OIDC handler | No | No | No | No |
| API scheme | JwtBearer | JwtBearer | JwtBearer + ClientToken | JwtBearer + ad-hoc hub token |
| Local password login | No | No (Keycloak) | No | No (Keycloak) |
| Cookie auth | Only for WebDisplay | No | No | No |
| `MapInboundClaims=false` | Yes | **No** | Yes | **No** |
| `ValidateAudience` | false | false | **true** (configurable) | false |
| `ValidateIssuer` | true | **configurable, off in dev** | true | true |
| Role claim | hardcoded `roles` | hardcoded `roles` | **configurable** | hardcoded `roles` |
| Userinfo enrichment | No | No | **Yes, cached 5 min** | No |
| Roles actually enforced | No | No | **Yes** (`Oidc:AdminRole`) | No |
| Local user table | **Yes** (`Users`) | No | No | No |
| Provisioning on first login | **Yes, lazy, per request** | n/a | n/a | n/a |
| Linked by | `sub` only | n/a | n/a | n/a |
| External-login table | No | No | No | No |
| Refresh tokens server-side | Only MAL, plaintext | No | No | No |
| Machine credentials | API key in config | none (dead schema) | per-server token, **plaintext** in DB | per-node token, **SHA-256** in DB |
| Secret encryption at rest | AES-GCM for stream tokens only | No | No | **AES-256-GCM vault** |
| 2FA | No | Keycloak (TOTP, recovery codes, WebAuthn) | No | Keycloak |
| Session store | None | None | None | None |
| DI shape | `AddAnimeAuthentication` + `AddAnimeAuthorization` | inline in `Program.cs` | `AddHopperAuthentication` + `AddHopperAuthorization` | inline in `Program.cs` |
| Runtime SPA config endpoint | `GET /api/app` | `GET /api/app` | `GET /api/app` | `GET /api/app` |
| Dev auth | in-process mock handler | mock-oauth2 container | mock-oauth2 container | mock-oauth2 container |
| DB providers | Postgres | SQLite + Postgres | (single) | SQLite + Postgres, **split migration assemblies** |
| Auth tests | ExternalApiKey only | none | **3 test classes** | none |

### Duplication, concretely

- The `AddJwtBearer` block appears four times, drifting on five separate settings.
- `HttpCurrentUserService` is byte-identical between CommandBlock and KRINT (doc comment
  included); HOPPER's differs only by member name (`Name` vs `GetActorName`).
- `auth.config.ts` is byte-identical between CommandBlock and KRINT; HOPPER's adds retry and a
  bootstrap-failure screen.
- `OAuth2SecuritySchemeTransformer` exists in all four, all with hardcoded Keycloak paths.
- `mock-oauth2-config.json` exists three times, differing only in client id, sub and email.
- The SignalR `OnMessageReceived` access-token block appears three times; only KRINT carries the
  `/hubs/node` exclusion.
- `AppQuery`/`AppController` exists four times, in three shapes (gaggaotaku adds `Mock`,
  CommandBlock and KRINT derive redirect from `PublicUrl`, HOPPER derives from request origin).

---

## Common core: what genuinely belongs in the package

Behaviour all four share, verbatim or near enough:

1. **Public authority versus internal authority.** Every one of them splits "the issuer the tokens
   claim" from "the address this container can reach for metadata", and sets `MetadataAddress`
   accordingly. This is a container/reverse-proxy fact of life and belongs in the options type.
2. **Raw JWT claim names.** `MapInboundClaims = false` is the intended state everywhere; two
   projects only fail to do it by accident. The package should default it off and never remap.
3. **The same five claims are read for identity:** `sub`, `preferred_username`, `email`, `name`,
   `picture`. The fallback chain `preferred_username ?? name ?? email` for a display name appears
   in three projects independently.
4. **Subject is the identity key.** Where a local user exists, `sub` is the join column, unique.
5. **Fallback policy requires an authenticated user**, with per-endpoint `[AllowAnonymous]` opt-out.
6. **A runtime configuration endpoint for the SPA**, so the frontend build is environment
   agnostic. All four have it; a package-provided endpoint plus DTO would delete four copies.
7. **Bearer token from the query string for WebSocket/SignalR handshakes**, path-scoped.
8. **Provider-agnostic by construction.** Nothing in the package may assume Keycloak's URL shape;
   everything comes from the discovery document. The four repos' hardcoded
   `/protocol/openid-connect/*` is the counter-example to avoid.
9. **Claim-to-local-profile projection plus get-or-create by subject** is the one provisioning
   behaviour that exists, and it is the thing Toamaisutaa should own outright (fixing the
   per-request write and the insert race in the process).

---

## Must stay configurable

Places where the four legitimately differ, so the package needs an extension point rather than a
decision:

| Concern | Why it cannot be hardcoded |
|---|---|
| Role claim name | `roles` (Keycloak realm roles) vs `groups` (Pocket ID, Authentik, Entra). HOPPER already learned this the hard way. |
| Where roles come from | Access token vs userinfo endpoint. Pocket ID, Okta and Entra keep groups out of the access token; others do not. Needs an on/off switch plus a cache. |
| Audience validation | HOPPER validates and lists audiences; the other three cannot, because their tokens' `aud` does not name the API. Default on, allow off. |
| Issuer validation | Normally on, but tunnel/preview deployments rewrite `iss`. Keep it configurable and make the name scary. |
| Scopes | `openid profile email roles` is the common default, but the role scope name is IdP-specific. |
| Redirect and post-logout URIs | Explicit value, else derived from a configured public URL, else derived from the request origin. All three strategies are in use. |
| Whether a local user row exists at all | gaggaotaku wants one; the other three deliberately have none. Provisioning must be opt-in, and the package must be useful without it. |
| Profile refresh policy | Sync claims on every request (gaggaotaku today, wasteful), only on first login, or when a claim actually changed. Consumer's call. |
| Claims to user mapping | `picture` matters to one app and not the others. This is the documented extension point in the Phase 2 brief and the evidence supports it. |
| Admin/role policy | HOPPER requires a role globally; the others require only authentication. |
| EF provider and migration assembly | SQLite + Postgres today, SQL Server plausible. KRINT's split-assembly pattern is the working precedent. |
| Encryption key source for anything at rest | KRINT uses a base64 master key from config with hard validation. Any secret the package stores needs the same seam. |
| Dev/test authentication | In-process fake handler vs external mock IdP. Both are in use and both are reasonable. |

---

## Contradictions I am not resolving on my own

1. **Machine secret storage: HOPPER stores tokens in plaintext, KRINT stores SHA-256 hashes.**
   Same author, same problem, opposite answers. (Out of Phase 2 scope, but it will come back when
   API keys or service tokens land in the package.)
2. **`MapInboundClaims`: off in gaggaotaku and HOPPER, on in CommandBlock and KRINT** - while all
   four configure raw claim names. I read this as drift rather than intent, but the package's
   default changes behaviour for two of your apps, so say so explicitly.
3. **Audience validation: on in HOPPER, off in the other three.** A secure default breaks three
   existing deployments on adoption.
4. **Dev auth: in-process bypass handler vs mock IdP container.** These are mutually exclusive
   designs and the package can only bless one as the documented path.
5. **Identity persistence: one app has a `Users` table, three deliberately do not.** This decides
   whether `IUserStore` is central or optional.

---

## Open questions before implementation

**Q1 (blocking, everything else depends on it). Which shape is Toamaisutaa's OIDC layer?**
The brief says `Microsoft.AspNetCore.Authentication.OpenIdConnect` with authorization code + PKCE,
which is the *server-side* flow: the server does the redirect, the code exchange and a sign-in
cookie. None of your four apps work that way; all four are SPA-front, bearer-back, and the code
flow never touches the server. Three options:
  a. Server-side OIDC only, as the brief literally says. Correct for server-rendered apps, new
     ground for you, and none of the four could adopt it without restructuring.
  b. Resource-server (JWT bearer) only, matching all four existing apps. Then "authorization code
     with PKCE" is the SPA's job, and the package's OIDC piece is validation, claims mapping,
     provisioning and linking.
  c. Both, with `AddToamaisutaaOidc` for the interactive flow and `AddToamaisutaaBearer` for the
     API. Largest surface, but it is the only answer that covers the apps you actually run.
I recommend (c) with (b) implemented first, since provisioning and linking - the parts with real
logic - are identical in both and the bearer path is the one with four consumers waiting.

**Q2. Multi-provider or single provider?** `IExternalLoginStore` and "linking by subject ID" imply
a `(Provider, Subject)` pair and therefore several IdPs per deployment. All four apps have exactly
one IdP. Do you want the multi-provider table shape now, or a single-provider shape with room to
grow?

**Q3. Composite key semantics.** If multi-provider: is the unique key `(ProviderKey, Subject)`, and
is `ProviderKey` the configured scheme name or the issuer URI from the discovery document? The
issuer is stabler; the scheme name is what consumers configure.

**Q4. Does email-based linking exist at all in v1?** The brief asks how collisions are handled,
but no analysed codebase links by email. My recommendation is subject-only linking in Phase 2,
with an explicit `LinkExisting` decision returned from `Core` so email linking can be added later
without a schema change. Confirm.

**Q5. User key type.** `Guid`, `string`, or generic `TKey`? The four apps use whatever
`BaseEntity` gives them. Generic keys double the API surface of every store; I would hardcode
`Guid` unless you object.

**Q6. Profile sync policy default.** On every request (today's behaviour, one `SaveChanges` per
request), on first login only, or on change only? I recommend on-change-only with a configurable
`ProfileSyncMode`.

**Q7. Does Phase 2 persist anything token-shaped?** "Token/session persistence through an
abstraction" is in the scope, but if the answer to Q1 is bearer-only, there is nothing to persist:
no refresh token, no session. If it is server-side OIDC, the refresh token has to live somewhere
and it must be encrypted at rest, which pulls a key-management seam into `Abstractions`.

**Q8. Which EF providers ship, and how?** Three options, and I want you to pick before anything is
generated:
  a. **Split migration assemblies**, KRINT's pattern: `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres`,
     `...SqlServer`, `...Sqlite`. Works, is proven in your own code, costs one package per provider.
  b. **Ship no migrations**; expose the entity configurations and let the consumer's own DbContext
     and migrations pick them up. Simplest for you, most work for consumers, and it gives up the
     TickerQ-style self-contained promise.
  c. **Runtime schema creation** from a provider-neutral script. Rejected: it fights EF and breaks
     the moment a consumer has their own migrations.
I recommend (a) for Postgres and SQLite first, since that is what your four apps use, with SQL
Server added on demand.

**Q9. Own DbContext or the consumer's?** TickerQ ships its own. Your apps have exactly one context
each and would probably rather have the tables in it. Both is possible but doubles the
documentation.

**Q10. Does `AddToamaisutaaOidc` own the authorization policy too?** HOPPER's admin-role policy and
the "authenticated by default" fallback are shared behaviour, but they are authorization, not
authentication, and folding them in makes the entry point do two things.

**Q11. The role/claims enrichment from userinfo - Phase 2 or later?** It is HOPPER's best idea and
the single most portable piece of code in the four repos. It also needs `IHttpClientFactory` and a
cache, so it belongs in `OpenIdConnect` rather than `Core`.

**Q12. Dev bypass in the package?** A `ToamaisutaaDevAuth` scheme would delete gaggaotaku's mock
handler, but shipping "authenticate everyone" inside an auth library is a liability. My inclination
is to document the mock-IdP container approach instead and ship nothing.

### Repo prerequisites, unrelated to design

While looking at `C:\Coding\Toamaisutaa` I found that it does not build today:

- `Directory.Build.props` is malformed. The package-metadata `<PropertyGroup>` and the `<ItemGroup>`
  sit **after** the closing `</Project>` tag, so no properties apply and
  `dotnet build src/Toamaisutaa.Abstractions` fails with `NETSDK1013: The TargetFramework value ""
  was not recognized`.
- There is no `Directory.Packages.props`, so central package management is declared but not set up.
- `assets/icon.png` is referenced by the packaging item group but only `assets/.gitkeep` exists.

I have not touched any of it. Say the word and I will fix these as the first step of Phase 2.
