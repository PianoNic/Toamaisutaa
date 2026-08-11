# Phase 3: proposed public API surface, local password login

Nothing implemented yet. Sign this off before I write code.

Two things in here contradict the brief. Both are flagged in place: **the D4 storage shape**, and
**a gap in D1 that the brief does not cover** (local users have no roles). Read those two sections
first if you read nothing else.

---

## 1. D4: the migration plan, and why I want to change the shape

The brief says `ToamaisutaaUser` gains nullable credential columns, and that the Phase 2 email index
becomes conditionally unique. I think that is the wrong shape, for three reasons that only became
visible when I worked through what the unique index actually does.

### The problem with columns on `ToamaisutaaUser`

**One: OIDC profile sync would silently rewrite a login identifier.** Phase 2's provisioning writes
`Email` onto the user row whenever the token's email claim changes (`ProfileSyncMode.OnChange`). If
the same `Email` column is also the unique local-login identifier, then an administrator changing a
user's email in Keycloak silently changes what that person types into your login form. Worse, if the
new value collides with another row, the unique index throws `DbUpdateException` from inside
`GetOrProvisionAsync` - on an unrelated GET request, during ordinary OIDC traffic. A profile field
and an identity key have different rules, and Phase 2 already treats `Email` as a profile field.

**Two: the conditional index is provider-specific in the model, not just in the migration.**
"Unique only for rows with a password" means a filtered index. EF Core expresses that with
`HasFilter("...")`, whose argument is raw SQL with provider-specific quoting
(`"PasswordHash" IS NOT NULL` for Postgres, `[PasswordHash] IS NOT NULL` for SQLite). That string
lives in the shared entity configuration, so one model would have to emit two different filters, and
the two migration assemblies would diverge from a single `IEntityTypeConfiguration`. It is solvable
with provider-conditional configuration; it is unpleasant, and it is the sort of thing that breaks
when a third provider arrives.

**Three: the migration can fail on real data.** An unfiltered unique index on email cannot be
created on a Phase 2 database where two OIDC users share an email, which happens whenever one person
has accounts at two providers, or an IdP recycles an address. The migration then fails at deploy
time, on the customer's data, with no remediation path in the package.

### What I want instead

A separate table, one row per local account:

```
ToamaisutaaPasswordCredentials
    UserId (PK, FK to ToamaisutaaUsers, cascade)
    NormalizedUserName   unique
    NormalizedEmail      unique
    UserName, Email      as entered, for display and for the reset flow
    PasswordHash         self-describing string, see D3
    SecurityStamp
    FailedAttemptCount, FirstFailedAttemptAt, LockedOutUntil
    CreatedAt, UpdatedAt
```

This gives, for free:

- **Phase 2 data is untouched.** The migration is purely additive: two new tables, no index change on
  `ToamaisutaaUsers`, no possibility of failing on existing rows. The one place this phase could
  break Phase 2 data stops existing.
- **The unique constraints are unconditional**, because only local accounts have a row. No filtered
  indexes, no provider-specific SQL in the model.
- **Identity and profile are separated.** OIDC sync writes `ToamaisutaaUser.Email`; it cannot touch
  `ToamaisutaaPasswordCredentials.NormalizedEmail`. Changing your login email becomes an explicit
  operation instead of a side effect of a token.
- **The model matches D4 exactly.** A user has zero or more external logins and zero or one password
  credential. That is the coexistence D4 asks for, expressed in the schema rather than in nullability
  conventions.

Cost: one join on the login path (by normalized identifier, into the credential row, then load the
user). Login is not a hot path, and it is one indexed lookup either way.

**Normalisation.** `NormalizedUserName` and `NormalizedEmail` are `ToUpperInvariant`, which is what
ASP.NET Identity does and what avoids depending on database collation - Postgres and SQLite disagree
about case-insensitive comparison, and I would rather not have identity semantics vary by provider.
The as-entered values are kept alongside for display.

**If you would rather I follow the brief literally**, say so and I will put the columns on
`ToamaisutaaUser` with a partial index per provider. I will also need to ship a pre-flight query for
operators to run against existing data, and the answer to "what should a deployment with duplicate
emails do" becomes a support question rather than a non-issue.

---

## 2. D1, and the gap: local users have no roles

D1 says the local access token carries "`sub`, `preferred_username`, `email`, `name`, and the
configured role claim". There is nowhere for those roles to come from. Phase 2 reads roles from the
IdP's token or its userinfo endpoint; this phase adds no roles table, and a roles table is not in
scope.

So as briefed, a local user can never satisfy `Oidc:AdminRole`, and the `Toamaisutaa.Admin` policy is
permanently unreachable for them. In a deployment that cannot run an IdP - the exact deployment this
feature exists for - that means no admin can log in at all.

I do not want to invent a roles table inside this phase. I propose the smallest seam that closes the
hole:

```csharp
/// Roles for a locally issued token. Ships returning nothing; a consumer with its own roles table
/// implements it in three lines.
public interface IUserRoleProvider
{
    Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default);
}
```

The default implementation returns an empty list, and the README says plainly that local accounts
have no roles until you supply them. **Tell me if you would rather have a real roles table now** -
it is a third table and a fourth endpoint group, and I would do it as its own phase.

### How the local token is validated by the Phase 2 pipeline

One `JwtBearer` handler, not two, so nothing downstream can tell the difference. The handler already
merges its discovery document's issuer and signing keys into whatever the options carry, so the
local issuer and key are added to `ValidIssuers` and `IssuerSigningKeys` and both token shapes
validate in the same pass.

I checked that against `JwtBearerHandler.HandleAuthenticateAsync` rather than trusting memory, since
the whole section depends on it. It clones the options' `TokenValidationParameters` and **concatenates**:

```csharp
tokenValidationParameters.ValidIssuers =
  (tokenValidationParameters.ValidIssuers == null ? issuers : tokenValidationParameters.ValidIssuers.Concat(issuers));
tokenValidationParameters.IssuerSigningKeys =
  (tokenValidationParameters.IssuerSigningKeys == null ? configuration.SigningKeys : tokenValidationParameters.IssuerSigningKeys.Concat(configuration.SigningKeys));
```

It also skips that block entirely when `ConfigurationManager` is null, which is what makes a
local-login-only deployment work with no `Oidc:Authority` configured at all. I will prove that one in
the sample rather than assert it.

One security detail that matters: with both key sets in one flat collection, a token claiming the
local issuer but signed with the IdP's key would validate, because the validator falls back to
trying every key when the `kid` does not match. That needs an authoritative source (the IdP) to go
rogue, so it is a low-likelihood attack, but binding the key to the issuer costs ten lines:

```csharp
options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
    IsLocalIssuer(securityToken.Issuer)
        ? [localKey]                                                   // only ours signs ours
        : parameters.IssuerSigningKeys.Where(key => key.KeyId != LocalKeyId);
```

**Signing key: symmetric HS256**, from `LocalLogin:SigningKey` as base64, validated at startup to
decode to at least 32 bytes. No ephemeral fallback: a generated-per-process key would silently
invalidate every token on restart and break outright across two instances, which is the failure mode
the analysis flagged in gaggaotaku's stream-proxy key. Asymmetric signing with a JWKS endpoint is
the right answer when another service needs to validate these tokens without holding the secret;
that is a later phase and I would rather not guess at its shape now.

**When password login is not registered, none of this exists.** The bearer layer reads the local
options and finds no key, so no local issuer is trusted. Phase 2 behaviour is bit-for-bit unchanged.

### Provisioning a locally issued token

`ICurrentUser.GetOrProvisionAsync` currently maps `(ProviderKey, sub)` to a user through
`ToamaisutaaExternalLogin`. A local token's `sub` is the user's own id, and there is no external
login row - so left alone, the provisioner would treat every local login as a never-seen subject and
create a duplicate user on every request.

Fix: the provisioner short-circuits when the token was issued by the local issuer, loading the user
by id. Keyed on the issuer, not on a claim, so an IdP cannot mint a token that takes this path -
and, because of the key resolver above, cannot claim the local issuer either.

---

## 3. Password hashing (D3)

Argon2id, parameters stored per row in a self-describing string:

```
$argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<hash-b64>
```

This is the standard PHC string format, so the row is readable by anything that speaks it and a
parameter change becomes a rehash-on-next-login rather than a schema change. Verification reads the
parameters out of the row; if they are weaker than the current configuration, the password is
rehashed with current parameters inside the same successful-login transaction.

Defaults per the current OWASP baseline: 19 MiB, 2 iterations, parallelism 1, 16-byte salt, 32-byte
output. Validated at startup to be no weaker than that.

### Library choice: Konscious, with the in-box PBKDF2 hasher shipped alongside it

Diligence done. The landscape:

- **.NET has no built-in Argon2 and is not getting one.** `dotnet/runtime#19933` has been open since
  January 2017, milestone "Future", labelled not-ready-for-implementation. The crypto team's stated
  position is that .NET delegates primitives to the platform and only OpenSSL implements Argon2, so
  it fails their two-platform bar. .NET 10 added PQC and AES key wrap, not this.
- **`Konscious.Security.Cryptography.Argon2` 1.3.1** (2024-06-19): pure managed, no native assets,
  ~8.4M downloads, passes the official test vectors, no CVEs or advisories. Targets up to `net8.0`,
  which resolves fine on net10.0. Downsides: the repo is in maintenance drift - last commit
  2024-06-18, ~17 open issues untriaged since 2019, and the .NET 8 target came from a community PR.
  It is also not strong-named.
- **`Isopoh.Cryptography.Argon2`** is the better-engineered one and is genuinely active right now -
  commits this month, and `master` already targets `net10.0`. But the published NuGet is still 2.0.0
  from 2023-08-17. The net10 work is not released.
- **`Argon2Sharp`** went native (Rust P/Invoke with per-RID binaries) at v4, so it is disqualified.
  `Soenneker.Hashing.Argon2` is a wrapper around Konscious plus three more packages.
- **In-box PBKDF2** (`Rfc2898DeriveBytes.Pbkdf2`) is zero-dependency and OWASP-sanctioned, but only
  as the FIPS-compliance option, at 600,000 SHA-256 iterations. It is not memory-hard, so it is
  materially weaker against GPU cracking - which is the entire threat this column defends against.

> **Decided against, and this is what shipped:** PBKDF2 only, no Argon2 package at all. The rule for
> anything in the credential path of a library other people consume is no external dependency
> without 10k+ stars and active maintenance, and no .NET Argon2 implementation meets it. The
> recommendation below is kept for the record; the reasoning about defaults was accepted, the
> conclusion was not. `Pbkdf2PasswordHasher` is the only shipped hasher, `IPasswordHasher` stays
> public so a consumer can register Argon2 themselves, and the PHC format means their rows
> interoperate with ours in both directions.

**Recommendation (not taken): Konscious for the default, and ship a PBKDF2 hasher next to it.**

Taking the dependency is the right call because the default matters more than anything else here:
whatever ships as the default is what almost every deployment will run forever, and a
non-memory-hard default is a permanent, real reduction in strength for every consumer. Dormancy is a
weaker argument against a cryptographic primitive than it looks - Argon2id is a frozen specification
(RFC 9106), this implementation passes the official vectors, and the open issues are memory and
ergonomics complaints rather than correctness or security defects. Primitives do not rot the way
protocol code does.

What makes the risk acceptable rather than merely tolerable is that D3's own design contains the
escape hatch. Because the algorithm and its parameters live in each row, I can ship **both** hashers
from day one:

```csharp
public sealed class Argon2idPasswordHasher : IPasswordHasher   // default
public sealed class Pbkdf2PasswordHasher : IPasswordHasher     // in-box, zero dependency, for FIPS
```

Both **verify** either format. So a consumer who must not carry the dependency, or who needs FIPS,
registers `Pbkdf2PasswordHasher` before `AddToamaisutaaPasswordLogin` and every existing Argon2 row
still verifies, then rehashes to PBKDF2 on next login through the rehash path that already has to
exist. The same mechanism carries us the other way if Konscious ever has to be dropped: swap the
implementation, existing rows keep working, and the fleet migrates itself as people log in. That is
one file and no migration, which is the property I want from a dependency I do not control.

The PHC prefixes are `$argon2id$` and `$pbkdf2-sha256$`. If Isopoh publishes a net10 release, moving
to it is the same one-file change.

Note this relaxes the Phase 1 rule that `Core` references only `Abstractions` and
`Microsoft.Extensions.*`. The brief already anticipates that; I am flagging it so it is a decision
and not a drift.

---

## 4. Abstractions

### Options

```csharp
public sealed class ToamaisutaaLocalLoginOptions          // section "LocalLogin"
{
    // Token issuance
    public string? SigningKey { get; set; }                        // base64, >= 32 bytes, required
    public string Issuer { get; set; } = "toamaisutaa";            // changing it invalidates live tokens
    public string? Audience { get; set; }                          // defaults to Oidc:ClientId
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);

    // Hashing
    public int MemoryKib { get; set; } = 19456;
    public int Iterations { get; set; } = 2;
    public int Parallelism { get; set; } = 1;

    // Lockout
    public bool LockoutEnabled { get; set; } = true;
    public int MaxFailedAttempts { get; set; } = 5;
    public TimeSpan LockoutWindow { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    // Passwords
    public int MinimumPasswordLength { get; set; } = 8;

    // Reset
    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    // Registration
    public bool AllowSelfRegistration { get; set; }                // false

    // Endpoints
    public string EndpointPrefix { get; set; } = "/auth";
}
```

`RefreshTokenAbsoluteLifetime` is not in the brief. Rotation alone means a session that is used once
a week never ends; the absolute cap on the family is what forces eventual re-authentication. Cut it
if you disagree and I will drop the column with it.

### Entities

```csharp
public class ToamaisutaaPasswordCredential
{
    public Guid UserId { get; set; }                 // primary key and foreign key
    public string UserName { get; set; }
    public string NormalizedUserName { get; set; }   // unique
    public string? Email { get; set; }
    public string? NormalizedEmail { get; set; }     // unique
    public string PasswordHash { get; set; }         // PHC string
    public string SecurityStamp { get; set; }
    public int FailedAttemptCount { get; set; }
    public DateTimeOffset? FirstFailedAttemptAt { get; set; }
    public DateTimeOffset? LockedOutUntil { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class ToamaisutaaRefreshToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid FamilyId { get; set; }               // indexed; the unit of revocation on reuse
    public string TokenHash { get; set; }            // unique; SHA-256 of the raw token
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset FamilyStartedAt { get; set; }
    public DateTimeOffset? RotatedAt { get; set; }   // set when exchanged; presenting it again is reuse
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
}

public class ToamaisutaaPasswordResetToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string TokenHash { get; set; }            // unique; SHA-256, same reasoning as refresh
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
```

`SecurityStamp` changes on every password change and on reset. It is not used for anything in this
phase beyond being written; it is there because 2FA and "sign out everywhere" both need it next
phase and adding a column later is a migration.

### Seams

```csharp
public interface IPasswordHasher
{
    string Hash(string password);
    PasswordVerificationResult Verify(string password, string hash);
}

public enum PasswordVerificationResult { Failed, Succeeded, SucceededRehashNeeded }

public interface IPasswordValidator
{
    /// Empty when the password is acceptable. Messages are shown to the person choosing it.
    IReadOnlyList<string> Validate(string password);
}

public interface IPasswordResetNotifier
{
    Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default);
}

public interface IUserRoleProvider   // see section 2
{
    Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default);
}

public interface IPasswordCredentialStore
{
    Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default);
    Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);
    Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default);
}

public interface IRefreshTokenStore
{
    Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default);
    Task MarkRotatedAsync(Guid tokenId, CancellationToken cancellationToken = default);
    Task RevokeAsync(Guid tokenId, string reason, CancellationToken cancellationToken = default);
    Task RevokeFamilyAsync(Guid familyId, string reason, CancellationToken cancellationToken = default);
    Task RevokeAllForUserAsync(Guid userId, string reason, CancellationToken cancellationToken = default);
    Task<int> DeleteExpiredAsync(DateTimeOffset olderThan, CancellationToken cancellationToken = default);
}

public interface IPasswordResetTokenStore
{
    Task CreateAsync(ToamaisutaaPasswordResetToken token, CancellationToken cancellationToken = default);
    Task<ToamaisutaaPasswordResetToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task MarkConsumedAsync(Guid tokenId, CancellationToken cancellationToken = default);
    Task InvalidateAllForUserAsync(Guid userId, CancellationToken cancellationToken = default);
}
```

`DeleteExpiredAsync` exists so a consumer can sweep; the package ships no background sweeper this
phase. Rows are small and a deployment can run it from its own scheduler. Say the word if you want a
hosted service.

### Services and DTOs

```csharp
public interface IPasswordSignInService
{
    Task<SignInResult> SignInAsync(string identifier, string password, CancellationToken cancellationToken = default);
    Task<SignInResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);
    Task SignOutAsync(string refreshToken, CancellationToken cancellationToken = default);
}

public interface IPasswordAccountService
{
    Task<AccountResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
    Task<AccountResult> SetPasswordAsync(Guid userId, string? currentPassword, string newPassword, CancellationToken cancellationToken = default);
    Task RequestPasswordResetAsync(string email, CancellationToken cancellationToken = default);
    Task<AccountResult> ResetPasswordAsync(string resetToken, string newPassword, CancellationToken cancellationToken = default);
}

public sealed record SignInResult
{
    public required SignInOutcome Outcome { get; init; }
    public TokenPair? Tokens { get; init; }
}

/// The outcome is for your logs. The endpoints collapse every failure into one response, per D6.
public enum SignInOutcome { Succeeded, InvalidCredentials, UnknownUser, LockedOut, RefreshTokenReused, RefreshTokenExpired }

public sealed record TokenPair
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
    public required int ExpiresIn { get; init; }        // seconds, OAuth-shaped
    public string TokenType => "Bearer";
}

public sealed record AccountResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
    public Guid? UserId { get; init; }
}

public sealed record LoginRequest(string Identifier, string Password);
public sealed record RefreshRequest(string RefreshToken);
public sealed record LogoutRequest(string RefreshToken);
public sealed record RegisterRequest(string UserName, string? Email, string Password);
public sealed record ChangePasswordRequest(string? CurrentPassword, string NewPassword);
public sealed record ForgotPasswordRequest(string Email);
public sealed record ResetPasswordRequest(string Token, string NewPassword);
```

---

## 5. Core

Public: `DefaultPasswordValidator` (length only), `Argon2PasswordHasher` (or its PBKDF2 equivalent),
`AddToamaisutaaPasswordLogin(...)`. Everything else internal and covered by tests through
`InternalsVisibleTo`:

- `PhcString` - parse and format the self-describing hash string.
- `LockoutPolicy` - window and threshold arithmetic, pure, no clock of its own beyond `TimeProvider`.
- `SecureTokens` - `RandomNumberGenerator.GetBytes(32)`, base64url, and the SHA-256 used for storage.
- `PasswordSignInService`, `PasswordAccountService` - the flows.

The reasoning about hashing refresh tokens with a fast unsalted SHA-256 rather than a KDF goes in a
comment on `SecureTokens`, so the next reader does not "fix" it: the input is 256 bits of
`RandomNumberGenerator` output, so there is nothing to brute-force and nothing for a salt to defend
against, and this runs on every refresh.

Timing equalisation: an unknown identifier verifies the presented password against a dummy hash
computed once at startup with the configured parameters, so the response time does not distinguish
"no such user" from "wrong password". Locked accounts pay the same cost.

---

## 6. EntityFrameworkCore

Three new configurations, all public for the same reason as Phase 2's, three new tables, two new
migrations. No change to `ToamaisutaaUsers` or its indexes.

```
ToamaisutaaPasswordCredentials    PK UserId, FK cascade, unique NormalizedUserName, unique NormalizedEmail
ToamaisutaaRefreshTokens          PK Id, FK UserId cascade, unique TokenHash, index (FamilyId), index (UserId)
ToamaisutaaPasswordResetTokens    PK Id, FK UserId cascade, unique TokenHash, index (UserId)
```

`AddToamaisutaaEntityFrameworkStores<TContext>()` gains the three new stores. Consumers on their own
`DbContext` pick them up through `ApplyToamaisutaaConfiguration()`, unchanged.

---

## 7. AspNetCore

```csharp
public static IServiceCollection AddToamaisutaaPasswordLogin(this IServiceCollection services, IConfiguration configuration, string sectionName = "LocalLogin");
public static IServiceCollection AddToamaisutaaPasswordLogin(this IServiceCollection services, Action<ToamaisutaaLocalLoginOptions> configure);

public static IEndpointConventionBuilder MapToamaisutaaPasswordEndpoints(this IEndpointRouteBuilder endpoints);
```

Endpoints, all anonymous except the last, all under `EndpointPrefix`:

| Method | Route | Body | Success | Failure |
|---|---|---|---|---|
| POST | `/auth/login` | `LoginRequest` | 200 `TokenPair` | 401, one body for wrong password, unknown user and lockout |
| POST | `/auth/refresh` | `RefreshRequest` | 200 `TokenPair` | 401, one body |
| POST | `/auth/logout` | `LogoutRequest` | 204 | 204 |
| POST | `/auth/register` | `RegisterRequest` | 201 `TokenPair` | 400 with validation errors, 409 if taken |
| POST | `/auth/password` | `ChangePasswordRequest` | 204 | 400, 401 |
| POST | `/auth/password/forgot` | `ForgotPasswordRequest` | 204 always | 204 always |
| POST | `/auth/password/reset` | `ResetPasswordRequest` | 204 | 400, one body |

`/auth/register` is mapped only when `AllowSelfRegistration` is true, per D8. `/auth/password`
requires an authenticated caller and covers both setting a first password on an OIDC account
(`CurrentPassword` null, allowed only when no credential exists) and changing an existing one
(`CurrentPassword` required). Both revoke every refresh token for the user, so a password change ends
other sessions.

`AddToamaisutaaPasswordLogin` fails fast at startup, in the same hosted-service check Phase 2 uses,
when `IPasswordResetNotifier` is missing, when the stores are missing, when `SigningKey` is absent or
decodes to fewer than 32 bytes, or when the Argon2 parameters are below the OWASP floor.

---

## 8. Test plan

Everything the brief listed, plus the ones I would want anyway:

- Verify against a known-good PHC string generated outside this codebase, so the format is not
  self-consistently wrong.
- Round-trip hash then verify; wrong password fails; malformed and truncated PHC strings fail
  closed rather than throwing.
- Rehash signalled when the stored parameters are weaker; not signalled when they match or exceed.
- Lockout: threshold exactly at and one below the limit, first failure outside the window resetting
  the counter, a successful login clearing it, expiry of `LockedOutUntil`.
- Refresh: rotation invalidates the presented token; the new token works; an expired token fails; a
  token past the family's absolute lifetime fails.
- Refresh reuse revokes the whole family, and every sibling token stops working.
- Reset token: single use, expiry, consumption revoking all refresh tokens, a second use failing.
- `SignInOutcome` differs internally for unknown user and wrong password while the endpoint returns
  the same status and body for both.
- Normalisation: `Nic@Example.COM` and `nic@example.com` are the same account; a second registration
  with a case variant is rejected.

Timing equalisation gets a test that asserts the dummy verification happened, not a wall-clock
comparison - timing assertions are flaky and prove little on a shared runner.

---

## What changed while implementing this

### One finding that needs a decision from you

**SQLite cannot range-query a `DateTimeOffset` column, and Phase 2's timestamps are all
`DateTimeOffset`.**

The cleanup sweep is the first code in this package that ever asked a database "which rows expired
before now". It threw on the first run of the sample:

```
The LINQ expression 'DbSet<ToamaisutaaRefreshToken>().ExecuteDelete()' could not be translated.
```

Reduced to a minimal case, equality and null checks on a `DateTimeOffset` column translate fine and
`<=` does not. That is EF Core being right rather than lazy: SQLite has no timestamp type, the value
is stored as text, and two instants written with different UTC offsets do not sort correctly as
strings.

Fixed for the three new tables by storing instants as Unix milliseconds through a value converter
(`InstantConverters`). The property stays a `DateTimeOffset`; only the column type changes, to
`bigint`. It sorts identically on both providers and translates on both.

**Phase 2's tables were left alone**, so this migration stays purely additive as promised. That
leaves `ToamaisutaaUsers.CreatedAt`, `UpdatedAt` and `ToamaisutaaExternalLogins.CreatedAt`,
`LastSignInAt` as timestamp columns that cannot be range-queried on SQLite. Nothing queries them
that way today. The next person who writes "delete users who have not signed in for a year" will hit
exactly this wall.

Three options, and I would rather you picked than have me guess:
- **Leave it.** Two column shapes in one schema, documented, and a trap waiting for a future query.
- **Unify in a follow-up phase** with a migration that converts the Phase 2 columns. Postgres needs a
  `USING` clause for `timestamptz` to `bigint`, so it is a hand-written migration, not a scaffolded
  one. Correct, and not additive.
- **Unify now**, before anything is published to NuGet, on the grounds that nobody has this schema in
  production yet. Cheapest moment it will ever be, if that assumption holds.

### Everything else that deviated

1. **`Pbkdf2PasswordHasher` is the only hasher**, per your hold on D3. `MemoryKib`, `Iterations` and
   `Parallelism` became `Pbkdf2Iterations` (600,000), `SaltSizeBytes` (16) and `HashSizeBytes` (32),
   all with a startup floor.
2. **Pepper and maximum password length**, added mid-implementation on your instruction. The pepper
   needed one thing the instruction did not mention: `RetiredPeppers`, a version-keyed map of
   superseded keys. Without it, rotating the pepper makes every existing row unverifiable at once,
   which is the opposite of rotating through the rehash path. The version marker lives in the
   algorithm name (`$pbkdf2-sha256-p1$`), so an unpeppered row, a current-pepper row and an
   old-pepper row are all distinguishable and all verifiable.
3. **`IUserStore` gained three methods**: `FindByEmailAsync` (to tell "no such person" from "owned by
   an identity provider" in the reset log), `CreateAsync(ToamaisutaaUser)` (local registration has no
   `ExternalUserProfile` to build a user from) and `DeleteAsync` (to take back a user row whose
   credential insert lost a race on the unique index, rather than leaving an account nobody can sign
   in to).
4. **`IPasswordCredentialStore.FindByNormalizedEmailAsync`** added. Reset looks up by email only:
   matching a user name there would send a link to an address the caller never named.
5. **`RequestPasswordResetAsync` returns `PasswordResetRequestOutcome`** rather than nothing, so
   `NoLocalCredential` is available to the caller's own logging as well as ours. The endpoint still
   answers 204 for every value.
6. **`AccountResult.Conflict`** added, so the registration endpoint can answer 409 for a taken
   identifier without turning every validation failure into one.
7. **`ToamaisutaaLocalLoginOptions.TokenCleanupInterval`** added for the opt-in sweep you approved.
8. **`IAccessTokenIssuer` is registered by `AddToamaisutaaBearer`**, and the password startup check
   requires it. Signing a token needs a JWT library, which `Core` does not carry, so the issuer lives
   in `OpenIdConnect` alongside the validation.
9. **Rate limiting needs `app.UseRateLimiter()`.** `RequireRateLimiting` is inert metadata without
   the middleware, and an endpoint mapping cannot add middleware to the pipeline. Documented on the
   method and in the sample; there is no way to detect it at runtime, which I do not love.

### A bug the tests caught

Removing a pepper while keeping the old key in `RetiredPeppers` failed every verification, because
the active version marker still matched an empty active slot and shadowed the retired entry. That is
precisely the "take the pepper back out" migration, so it would have been found in production
instead. `TryResolvePepper` now treats the active version as meaningful only while there is an active
pepper.

## Open items

1. **The hashing dependency**: `Konscious.Security.Cryptography.Argon2` 1.3.1 as the default, with
   `Pbkdf2PasswordHasher` shipped alongside for FIPS or dependency-free deployments, and both able to
   verify either format. Reasoning in section 3. This is the only new third-party dependency in the
   phase; confirm before I add it to `Directory.Packages.props`.
2. **D4 storage shape** - separate table as recommended in section 1, or columns on
   `ToamaisutaaUser` as briefed.
3. **Roles for local users** - the `IUserRoleProvider` seam, or a real roles table as its own phase,
   or accept that local accounts cannot be admins.
4. **Registration leaks account existence** by design: "username taken" is a 409. Avoiding that needs
   email verification, which needs the delivery mechanism D7 keeps out of the package. I propose
   accepting it and saying so in the README, since registration is off by default anyway.
5. **`RefreshTokenAbsoluteLifetime`** - keep or cut.
6. **Refresh token sweeping** - store method only, or a hosted service that runs it.
