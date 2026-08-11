# Phase 2: proposed public API surface

Bearer resource server only, per the Phase 2 brief. Nothing here is implemented yet. Sign this off
(or argue with it) before I write code.

Everything not listed below is `internal`. Every public type has a one-line justification, because
public means permanent.

---

## Step zero: done

- `Directory.Build.props` rewritten as a single well-formed `<Project>` element. The `PackageIcon`
  property and the `assets\icon.png` `<None>` item are commented out, paired, with a note to restore
  both when you supply the file. No placeholder image generated.
- `Directory.Packages.props` created with `ManagePackageVersionsCentrally`. Both existing versions
  moved out of the csproj files (`TUnit`, `Microsoft.AspNetCore.OpenApi`), which now carry bare
  `<PackageReference Include="..." />`.
- `dotnet build Toamaisutaa.slnx`: **0 warnings, 0 errors**, all seven projects.

One judgement call I made without asking: the first clean build reported `NU1903` because
`Microsoft.AspNetCore.OpenApi 10.0.10` drags in `Microsoft.OpenApi 2.0.0`, which carries a known
high-severity advisory (GHSA-v5pm-xwqc-g5wc). I turned on `CentralPackageTransitivePinningEnabled`
and pinned `Microsoft.OpenApi` to `2.11.0` - same major, no API change. Say the word if you would
rather carry the warning.

---

## Naming decisions I need you to confirm

1. **Options type is `ToamaisutaaOidcOptions`, not `ToamaisutaaBearerOptions`.** The original brief
   named it that, and everything in it (authority, client id, scopes, redirect URIs, claim names) is
   shared with the future interactive flow. Renaming it later would be a breaking change; naming it
   after the transport now guarantees one.
2. **Display-name fallback order.** Your brief says `preferred_username ?? name ?? email`. That is
   the order the three audit-string implementations use for an *actor* string, but gaggaotaku - the
   only app that stores a display name - uses `name ?? preferred_username`. For a field called
   `DisplayName` I would expect `name` to win, since `name` is the human's name and
   `preferred_username` is a handle. I have written the surface with **your** order and made it
   configurable per Q&A below, but tell me which you actually want as the default.
3. **`IUserStore` collides by simple name with `Microsoft.AspNetCore.Identity.IUserStore<TUser>`.**
   Only matters for consumers who use both, and only in a `using`-ambiguity sense. I kept your name.

---

## Toamaisutaa.Abstractions

Zero package references. Only BCL types (`System.Security.Claims`, `System.Collections.Generic`).

### Options

```csharp
namespace Toamaisutaa.Abstractions;

/// Everything read from the "Oidc" configuration section. Shared with the future interactive flow.
public sealed class ToamaisutaaOidcOptions
{
    // Discovery and validation
    public string? Authority { get; set; }
    public string? InternalAuthority { get; set; }          // metadata reachable inside the network
    public string? ClientId { get; set; }
    public bool RequireHttpsMetadata { get; set; } = true;
    public bool ValidateIssuer { get; set; } = true;
    public bool ValidateAudience { get; set; } = true;      // default true, per HOPPER
    public IList<string> ValidAudiences { get; set; } = new List<string>();   // falls back to [ClientId]

    // Claim types on the resulting identity
    public string NameClaim { get; set; } = "name";
    public string RoleClaim { get; set; } = "roles";

    // Userinfo enrichment
    public bool FetchClaimsFromUserInfo { get; set; } = true;
    public TimeSpan UserInfoCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    // Served to the SPA by the configuration endpoint
    public string Scope { get; set; } = "openid profile email roles";
    public string? RedirectUri { get; set; }
    public string? PostLogoutRedirectUri { get; set; }
    public string? PublicUrl { get; set; }                  // used to derive the two above

    // WebSocket / SignalR handshake support
    public ToamaisutaaQueryTokenOptions QueryToken { get; set; } = new();
}

/// Bearer token read from the query string, because browsers cannot set headers on a WS handshake.
public sealed class ToamaisutaaQueryTokenOptions
{
    public string ParameterName { get; set; } = "access_token";
    public IList<string> IncludePaths { get; set; } = new List<string>();   // e.g. "/hubs"
    public IList<string> ExcludePaths { get; set; } = new List<string>();   // e.g. "/hubs/node"
}
```

Property names deliberately match the configuration keys your four apps already use
(`Oidc:RoleClaim`, `Oidc:FetchClaimsFromUserInfo`, `Oidc:ValidAudiences:0`, ...), so adoption is a
delete-and-register rather than a re-key. There is **no** `Enabled` flag on `QueryToken`: an empty
`IncludePaths` means the feature is off, which removes the "enabled but scoped to nothing" state.

```csharp
public sealed class ToamaisutaaAuthorizationOptions
{
    public bool RequireAuthenticatedUser { get; set; } = true;   // the fallback policy
    public string? AdminRole { get; set; }                       // null = no admin policy at all
    public string AdminPolicyName { get; set; } = "Toamaisutaa.Admin";
    public bool RequireAdminRoleGlobally { get; set; } = false;  // HOPPER's whole-app-is-admin shape
}

public sealed class ToamaisutaaProvisioningOptions
{
    public string ProviderKey { get; set; } = ToamaisutaaDefaults.ProviderKey;
    public ProfileSyncMode ProfileSyncMode { get; set; } = ProfileSyncMode.OnChange;
    public ToamaisutaaClaimNames ClaimNames { get; set; } = new();
}

public enum ProfileSyncMode { Never, FirstSignInOnly, OnChange, EveryRequest }

/// Which claim types the default mapper reads. Provider-agnostic, so it is configuration, not code.
public sealed class ToamaisutaaClaimNames
{
    public string Subject { get; set; } = "sub";
    public string Issuer { get; set; } = "iss";
    public string UserName { get; set; } = "preferred_username";
    public string Email { get; set; } = "email";
    public string DisplayName { get; set; } = "name";
    public string Picture { get; set; } = "picture";
}
```

### Entities and DTOs

```csharp
/// The local user row. A plain POCO so Abstractions stays dependency-free; EF configures it.
public class ToamaisutaaUser
{
    public Guid Id { get; set; }
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public string? DisplayName { get; set; }
    public string? PictureUrl { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// One (provider, subject) pair pointing at a local user.
public class ToamaisutaaExternalLogin
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string ProviderKey { get; set; } = default!;   // the authentication scheme name
    public string Subject { get; set; } = default!;       // the "sub" claim
    public string? Issuer { get; set; }                   // non-key, so the key can migrate later
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastSignInAt { get; set; }
}

/// What the claims mapper produces: the identity as the provider describes it, nothing local.
public sealed record ExternalUserProfile
{
    public required string Subject { get; init; }
    public string? Issuer { get; init; }
    public string? UserName { get; init; }
    public string? Email { get; init; }
    public string? DisplayName { get; init; }   // already resolved through the fallback chain
    public string? PictureUrl { get; init; }
}

/// Served to the SPA so the frontend build stays environment-agnostic. Replaces four copies of AppQuery.
public sealed record ToamaisutaaClientConfiguration
{
    public required string Authority { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string PostLogoutRedirectUri { get; init; }
    public required string Scope { get; init; }
}

public static class ToamaisutaaDefaults
{
    public const string ProviderKey = "Bearer";                        // == the scheme name
    public const string UserInfoHttpClientName = "toamaisutaa-userinfo";
    public const string ConfigurationEndpointPattern = "/api/app";
}
```

No navigation property from `ToamaisutaaUser` to its logins: it would push an EF-shaped concern into
a dependency-free POCO and invites lazy-loading surprises. Go through `IExternalLoginStore`.

### Stores

```csharp
public interface IUserStore
{
    Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default);
    Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default);
}

public interface IExternalLoginStore
{
    Task<ToamaisutaaExternalLogin?> FindAsync(string providerKey, string subject, CancellationToken cancellationToken = default);
    /// Throws <see cref="ExternalLoginConflictException"/> when the (provider, subject) pair already exists.
    Task<ToamaisutaaExternalLogin> LinkAsync(Guid userId, ExternalUserProfile profile, string providerKey, CancellationToken cancellationToken = default);
    Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default);
}

/// The unique index on (ProviderKey, Subject) fired. Lets Core handle the first-sign-in race
/// without Core ever seeing an EF type.
public sealed class ExternalLoginConflictException : Exception
{
    public ExternalLoginConflictException(string providerKey, string subject, Exception? innerException = null);
    public string ProviderKey { get; }
    public string Subject { get; }
}
```

### Behaviour seams

```csharp
/// THE documented extension point. Replace to map claims your way.
public interface IClaimsProfileMapper
{
    ExternalUserProfile Map(ClaimsPrincipal principal);
}

/// Decides what provisioning should do. Public because it is where email-based linking lands later.
public interface IProvisioningPolicy
{
    ProvisioningDecision Decide(ProvisioningContext context);
}

public sealed record ProvisioningContext
{
    public required string ProviderKey { get; init; }
    public required ExternalUserProfile Profile { get; init; }
    public required ProfileSyncMode SyncMode { get; init; }
    public ToamaisutaaExternalLogin? ExistingLogin { get; init; }
    public ToamaisutaaUser? LinkedUser { get; init; }      // the user behind ExistingLogin
    public ToamaisutaaUser? LinkCandidate { get; init; }   // reserved; always null in v1
}

public enum ProvisioningAction { AlreadyLinked, LinkExisting, CreateNew }

public sealed record ProvisioningDecision
{
    public required ProvisioningAction Action { get; init; }
    public Guid? UserId { get; init; }
    public Guid? ExternalLoginId { get; init; }
    public bool ProfileNeedsUpdate { get; init; }
}

/// Runs the decision against the stores. Idempotent, race-safe.
public interface IExternalLoginProvisioner
{
    Task<ToamaisutaaUser> ProvisionAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);
}

/// What application code injects. Deliberately not HTTP-shaped, so an Application layer can depend
/// on it with no ASP.NET reference - which is exactly what all four of your apps do today.
public interface ICurrentUser
{
    bool IsAuthenticated { get; }
    string? Subject { get; }
    string? Name { get; }        // preferred_username ?? name ?? email, for audit strings
    /// Get-or-create the local row. Memoised per request. Throws if unauthenticated.
    Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default);
}
```

`LinkCandidate` is always `null` in v1 (subject-only linking, Q4), so `LinkExisting` is unreachable
today. It exists now so that adding email linking later is a new `IProvisioningPolicy`, not a new
signature and not a migration.

---

## Toamaisutaa.Core

References `Abstractions` plus `Microsoft.Extensions.{DependencyInjection.Abstractions,Options,Logging.Abstractions}`.
No ASP.NET, no EF, no `HttpClient`. Usable from a console app or worker.

```csharp
namespace Toamaisutaa.Core;

/// Public so a custom mapper can delegate to it for the parts it does not care about.
public sealed class DefaultClaimsProfileMapper : IClaimsProfileMapper
{
    public DefaultClaimsProfileMapper(IOptions<ToamaisutaaProvisioningOptions> options);
    public ExternalUserProfile Map(ClaimsPrincipal principal);
}
```

```csharp
namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaCoreServiceCollectionExtensions
{
    /// Opt-in. Registers the mapper, the policy and the provisioner. Stores come from a separate
    /// call, so this throws nothing and does nothing useful until an IUserStore is registered.
    public static IServiceCollection AddToamaisutaaProvisioning(
        this IServiceCollection services,
        Action<ToamaisutaaProvisioningOptions>? configure = null);
}
```

Internal to Core, reachable from tests via `InternalsVisibleTo("Toamaisutaa.Core.Tests")`:

- `DefaultProvisioningPolicy` - the decision matrix.
- `ProfileComparer` - whether a mapped profile differs from a stored row, which is what makes
  `ProfileSyncMode.OnChange` mean anything.
- `ExternalLoginProvisioner` - orchestration, including catch-conflict-and-re-read once.
- `ClaimsJsonFlattener` - **userinfo JSON to claims, including array flattening.** This is pure
  logic with no HTTP in it, so it lives in Core where it is testable without a web host. The
  fetching, caching and merging around it live in `OpenIdConnect`.
- `UserInfoDecision.ShouldFetch(...)` - the "role claim is missing and enrichment is enabled"
  predicate, same reasoning.

The decision matrix, so you can check it before I write it:

| ExistingLogin | LinkCandidate | Action | ProfileNeedsUpdate |
|---|---|---|---|
| found | - | `AlreadyLinked` | `Never` no, `FirstSignInOnly` no, `OnChange` only if the profile differs, `EveryRequest` yes |
| none | none | `CreateNew` | n/a, the insert writes the profile |
| none | present | `LinkExisting` | `Never` no, otherwise yes |

---

## Toamaisutaa.EntityFrameworkCore

References `Core` plus `Microsoft.EntityFrameworkCore.Relational`.

```csharp
namespace Toamaisutaa.EntityFrameworkCore;

/// For consumers who want the tables in their own context rather than ours.
public sealed class ToamaisutaaUserConfiguration : IEntityTypeConfiguration<ToamaisutaaUser>;
public sealed class ToamaisutaaExternalLoginConfiguration : IEntityTypeConfiguration<ToamaisutaaExternalLogin>;

/// Ships the tables standalone, TickerQ-style.
public class ToamaisutaaDbContext : DbContext
{
    public ToamaisutaaDbContext(DbContextOptions<ToamaisutaaDbContext> options);
    public DbSet<ToamaisutaaUser> Users { get; }
    public DbSet<ToamaisutaaExternalLogin> ExternalLogins { get; }
    protected override void OnModelCreating(ModelBuilder modelBuilder);
}

public static class ToamaisutaaModelBuilderExtensions
{
    /// One line inside your own OnModelCreating instead of two ApplyConfiguration calls.
    public static ModelBuilder ApplyToamaisutaaConfiguration(this ModelBuilder modelBuilder);
}
```

```csharp
namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaEntityFrameworkServiceCollectionExtensions
{
    /// Stores backed by the consumer's own DbContext.
    public static IServiceCollection AddToamaisutaaEntityFrameworkStores<TContext>(this IServiceCollection services)
        where TContext : DbContext;

    /// Stores backed by our own ToamaisutaaDbContext.
    public static IServiceCollection AddToamaisutaaDbContext(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> configure);
}
```

Schema:

| Table | Column | Notes |
|---|---|---|
| `ToamaisutaaUsers` | `Id` | `Guid`, PK, no value generation (the store assigns) |
| | `UserName`, `Email`, `DisplayName` | max length 256 |
| | `PictureUrl` | max length 2048 |
| | `CreatedAt`, `UpdatedAt` | `DateTimeOffset` |
| | index | `Email`, non-unique (lookup, not identity; email linking is out of scope) |
| `ToamaisutaaExternalLogins` | `Id` | `Guid`, PK |
| | `UserId` | FK to `ToamaisutaaUsers`, cascade delete, indexed |
| | `ProviderKey` | max length 128, required |
| | `Subject` | max length 256, required |
| | `Issuer` | max length 512, nullable |
| | `CreatedAt`, `LastSignInAt` | |
| | index | **unique on (`ProviderKey`, `Subject`)** |

Fixed table names, no schema qualifier, because SQLite has none. If you want different names, use
the `ApplyToamaisutaaConfiguration` path and call `.ToTable(...)` after it.

`Guid` primary keys assigned by the store rather than the database: it keeps the two providers
identical and lets the provisioner write user and login in one `SaveChanges`. UUIDv7 via
`Guid.CreateVersion7()` so the keys stay index-friendly.

### Migration assemblies

Two new projects, following KRINT's precedent exactly:

- `src/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` (`Npgsql.EntityFrameworkCore.PostgreSQL`)
- `src/Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite` (`Microsoft.EntityFrameworkCore.Sqlite`)

Each holds one migration and its model snapshot plus an `IDesignTimeDbContextFactory<ToamaisutaaDbContext>`
so `dotnet ef migrations add` works without a host. Selected by the consumer:

```csharp
services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
```

Three things you should know before I generate anything:

1. **This only covers the `ToamaisutaaDbContext` path.** A consumer who applies the configurations
   into their own context generates their own migration, which is correct and unavoidable. It will
   be one paragraph in the README.
2. **`MigrationsAssembly` has to be set by the consumer**, because it is part of the provider
   options. I can wrap it (`db.UseToamaisutaaPostgres(cs)`) to make it one call, but that puts a
   provider package reference in a place that then has to carry all of them. I would rather
   document the line. Tell me if you want the sugar.
3. **Adding SQL Server later is a third project**, not a change to these two.

---

## Toamaisutaa.OpenIdConnect

References `Core`, `<FrameworkReference Include="Microsoft.AspNetCore.App" />`. Public surface is
two extension methods and nothing else.

```csharp
namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaBearerExtensions
{
    /// Binds ToamaisutaaOidcOptions from configuration (default section "Oidc") and adds JwtBearer.
    /// Returns the AuthenticationBuilder so consumers can chain their own schemes, as HOPPER does.
    public static AuthenticationBuilder AddToamaisutaaBearer(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "Oidc");

    public static AuthenticationBuilder AddToamaisutaaBearer(
        this IServiceCollection services,
        Action<ToamaisutaaOidcOptions> configure);
}
```

`AddToamaisutaaOidc` is **not** defined. It is reserved for the interactive server-side flow.

What it wires, all internal:

- `MapInboundClaims = false`, unconditionally and not configurable. Behaviour change for CommandBlock
  and KRINT; it goes in the README migration notes.
- `MetadataAddress` from `InternalAuthority` when it differs from `Authority`, `ValidIssuer` always
  the public `Authority`. Nothing constructs a provider-specific path; the discovery document is the
  only source of endpoints.
- `NameClaimType` / `RoleClaimType` from options.
- `ValidateAudience` default true, `ValidAudiences` falling back to `[ClientId]`.
- `OnMessageReceived`: query-string token, only for `IncludePaths`, never for `ExcludePaths`.
- `OnTokenValidated`: userinfo enrichment. Fires only when enrichment is on and the configured role
  claim is absent from the token. Discovers the userinfo endpoint from the configuration manager,
  flattens the response (arrays become one claim per entry so `IsInRole` matches a single group),
  adds only claims the identity does not already carry, and on any failure logs a warning and
  decides on the token's own claims. Cached per `(providerKey, subject)` for
  `UserInfoCacheDuration`. **Not** keyed on `token.GetHashCode()`, which is HOPPER's one real bug
  here: 32-bit, non-cryptographic, process-randomised, and a collision serves one user another
  user's roles.
- `OnForbidden`: HOPPER's diagnostic, kept nearly verbatim. Logs which claim was read, what the
  principal actually carried there, and every claim type present, then points at `Oidc:RoleClaim`.
  Reads `HttpContext.User`, not `context.Principal`, for the reason HOPPER's comment gives.
- Registers `AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName)` and `AddMemoryCache()`.

---

## Toamaisutaa.AspNetCore

References `Core`, `<FrameworkReference Include="Microsoft.AspNetCore.App" />`.

```csharp
namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaAuthorizationExtensions
{
    public static IServiceCollection AddToamaisutaaAuthorization(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "Oidc");

    public static IServiceCollection AddToamaisutaaAuthorization(
        this IServiceCollection services,
        Action<ToamaisutaaAuthorizationOptions> configure);

    /// Registers ICurrentUser. Separate call, because provisioning is opt-in.
    public static IServiceCollection AddToamaisutaaCurrentUser(this IServiceCollection services);
}
```

```csharp
namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaEndpointRouteBuilderExtensions
{
    /// GET /api/app - the runtime OIDC config for the SPA. Anonymous by default, since the
    /// fallback policy would otherwise make it unreachable before sign-in.
    public static IEndpointConventionBuilder MapToamaisutaaConfiguration(
        this IEndpointRouteBuilder endpoints,
        string pattern = ToamaisutaaDefaults.ConfigurationEndpointPattern);
}
```

`AddToamaisutaaAuthorization` sets the fallback policy to `RequireAuthenticatedUser()`, plus
`RequireRole(AdminRole)` when `RequireAdminRoleGlobally` is set, and registers the named admin
policy when `AdminRole` is set. It does not touch authentication and does not require
`AddToamaisutaaBearer`; the two are independent, per Q10.

Redirect URI resolution for the config endpoint, in order: `Oidc:RedirectUri`, else `Oidc:PublicUrl`,
else the request's own origin. That is the union of what your four apps do, in the order they do it.

---

## Wiring, end to end

Minimum, no local user table (what CommandBlock, HOPPER and KRINT would use):

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);
// ...
app.MapToamaisutaaConfiguration();
```

With provisioning (what gaggaotaku would use):

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);
builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(cs,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
builder.Services.AddToamaisutaaCurrentUser();
```

Four calls is more ceremony than one `AddToamaisutaa(...)` would be, but each maps to a decision you
made (auth separate from authorization, provisioning opt-in, stores swappable), and a single
god-method would have to guess all three.

---

## Test plan (TUnit, `Toamaisutaa.Core.Tests`)

- **Claims mapping**: subject read from `sub`; every optional claim absent maps to null; custom
  `ClaimNames` respected; missing `sub` throws rather than producing a subject-less profile.
- **Display-name fallback chain**: each of the three positions wins in turn, and all three absent
  gives null.
- **Profile comparison**: same values, one value differs, null-to-value, value-to-null.
- **Provisioning decision matrix**: every cell of the table above, all four sync modes.
- **Userinfo flattening**: string, number, bool, string array (one claim per entry), nested object
  skipped, array of objects skipped, empty string skipped, non-object root gives empty.
- **Userinfo fetch predicate**: disabled, role claim already present, role claim absent.
- **Race handling**: a store stub that throws `ExternalLoginConflictException` on first
  `LinkAsync` and returns the winning row on re-read produces one user, no exception.

---

## What changed while implementing this

Six deviations from the surface above, all found in the code rather than at design time.

1. **`IToamaisutaaClientConfigurationProvider` lives in `Toamaisutaa.AspNetCore`, not
   `Abstractions`.** Its signature takes an `HttpContext` - which is right, since the last fallback
   for the redirect URI is the request's own origin - and `Abstractions` has zero dependencies.
   `ToamaisutaaClientConfiguration`, the DTO it returns, is still in `Abstractions`.
2. **Added `AddToamaisutaaClientConfiguration()`** so the provider can be registered without the
   authorization policy, for an application that composes the config into its own endpoint.
   `AddToamaisutaaAuthorization` calls it, so the common path is unchanged.
3. **Added `ToamaisutaaProvisioningOptions.SignInStampInterval`** (default one hour). Writing
   `LastSignInAt` on every request would have reintroduced exactly the per-request write that
   `ProfileSyncMode` exists to remove. `Never` never stamps, `EveryRequest` always does, and the
   modes in between stamp at most once per interval.
4. **`Microsoft.AspNetCore.Authentication.JwtBearer` is a `PackageReference` in
   `Toamaisutaa.OpenIdConnect`.** It has not been part of the shared framework since ASP.NET Core
   3.0, so `FrameworkReference` alone does not supply it. The framework reference is still there for
   everything else, and no framework assembly is referenced as a package.
5. **The two EF stores are one internal class implementing both interfaces.** They share a
   `DbContext` regardless, and one object can tell whether the user it is linking was created by
   this same request. That is what lets the losing side of a concurrent first sign-in delete the
   user row it just created, instead of leaving one behind with no login attached. A user someone
   else created is never touched.
6. **The fail-fast check is an `IHostedService`, not options validation.** `IValidateOptions` cannot
   see the service collection, and resolving a scoped `IUserStore` from the root provider to check
   for its presence throws for an unrelated reason. The hosted service inspects the registrations at
   startup and names the missing call.

Two transitive package pins were needed to keep the build at zero warnings:
`Microsoft.OpenApi` to 2.11.0 (GHSA-v5pm-xwqc-g5wc) and `SQLitePCLRaw.lib.e_sqlite3` to 2.1.12
(GHSA-2m69-gcr7-jv3q). Both are same-major patches, pinned via
`CentralPackageTransitivePinningEnabled`.

## Open items for you

1. Display-name fallback order (see naming decision 2). Default as briefed unless you say otherwise.
2. `UseToamaisutaaPostgres(cs)` sugar for `MigrationsAssembly`, yes or no.
3. `Guid` v7 keys assigned in the store rather than by the database - confirm.
4. Fixed table names `ToamaisutaaUsers` / `ToamaisutaaExternalLogins` - confirm.
5. Should `AddToamaisutaaProvisioning()` fail fast at startup when no `IUserStore` is registered? I
   would rather it threw a clear "you forgot AddToamaisutaaEntityFrameworkStores" than resolve to a
   missing-service error at the first request.
