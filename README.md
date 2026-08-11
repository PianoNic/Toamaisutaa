# Toamaisutaa

**トアマイスター** / Toamaisutaa / "gate master" - German *Tormeister* run through katakana and back
out again.

Authentication for ASP.NET Core, packaged: OIDC token validation, claims mapping, optional user
provisioning, and its own EF Core migrations.

This release covers the **bearer resource-server** path. The authorization-code flow with PKCE runs
in your client; Toamaisutaa validates what it sends and gives you a local user if you want one.
Server-side interactive sign-in and local password login are later phases and are deliberately
absent rather than stubbed.

## Packages

| Package | Contains |
|---|---|
| `Toamaisutaa.Abstractions` | interfaces, options, DTOs. No dependencies at all |
| `Toamaisutaa.Core` | claims mapping, the provisioning decision, linking rules. No ASP.NET, no EF |
| `Toamaisutaa.OpenIdConnect` | `AddToamaisutaaBearer`, JWT validation, userinfo enrichment |
| `Toamaisutaa.AspNetCore` | authorization, `ICurrentUser`, the SPA configuration endpoint |
| `Toamaisutaa.EntityFrameworkCore` | entities, configurations, stores, `ToamaisutaaDbContext` |
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
