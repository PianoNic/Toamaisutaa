# Storage and migrations

Provisioning is opt-in. The package is fully usable with no local user table at all, letting the
identity provider own every user.

Add it when you want a row of your own to hang data off.

## Two ways to hold the tables

**Our context**, when you would rather not touch yours:

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
```

**Yours**, when you would rather keep one database context:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    base.OnModelCreating(modelBuilder);
    modelBuilder.ApplyToamaisutaaConfiguration(Database);
}
```

```csharp
builder.Services.AddToamaisutaaEntityFrameworkStores<YourDbContext>();
```

The entity configurations are public, so you can also apply them individually and call `.ToTable()`
afterwards to rename anything. Generate the migration in your own project - the shipped migration
packages only cover `ToamaisutaaDbContext`.

## Why migrations ship as separate packages

EF Core cannot hold two providers' migration sets and model snapshots in one assembly. So each
provider gets its own package, and the consumer names it:

| Provider | Package | Options call | Migrations assembly |
|---|---|---|---|
| PostgreSQL | `…Migrations.Postgres` | `UseNpgsql` | `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` |
| SQLite | `…Migrations.Sqlite` | `UseSqlite` | `Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite` |
| SQL Server | `…Migrations.SqlServer` | `UseSqlServer` | `Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer` |
| MySQL | `…Migrations.MySql` | `UseMySQL` | `Toamaisutaa.EntityFrameworkCore.Migrations.MySql` |

```csharp
// PostgreSQL
db.UseNpgsql(cs, o => o.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres"));

// SQL Server
db.UseSqlServer(cs, o => o.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer"));

// MySQL
db.UseMySQL(cs, o => o.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.MySql"));

// SQLite
db.UseSqlite(cs, o => o.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite"));
```

Install only the one you use. Each pulls its own database driver, and none of them is a dependency
of `Toamaisutaa.EntityFrameworkCore` itself.

### A note on the MySQL provider

The MySQL package builds on Oracle's `MySql.EntityFrameworkCore`, not the more commonly used
[Pomelo](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql), because Pomelo has
no EF Core 10 release.

### Subjects are case-sensitive, and SQL Server and MySQL are not

An OpenID Connect subject is compared exactly, but the default collations on SQL Server and MySQL
ignore case (and MySQL's ignores accents), so `alice` and `ALICE` would collide on the unique index.
The shipped migrations give the column a binary collation on those two - `Latin1_General_100_BIN2`
and `utf8mb4_bin`. PostgreSQL and SQLite compare exactly already.

**With your own context**, pass its `Database` so the model knows which provider it is for, then
generate the migration:

```csharp
modelBuilder.ApplyToamaisutaaConfiguration(Database);
```

On MySQL, check the generated migration before applying it. `MySql.EntityFrameworkCore` leaves the
collation out of the `MODIFY` it generates, so the migration applies and changes nothing; the shipped
one is written as SQL for that reason:

```sql
ALTER TABLE `ToamaisutaaExternalLogins` MODIFY `Subject` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
```

A database left comparing without case still refuses the second subject, with an error naming the
collation rather than a bare conflict.

## Not using Entity Framework at all

`Toamaisutaa.EntityFrameworkCore` is one implementation of a set of interfaces, not the storage
layer. `Toamaisutaa.Core` depends on the interfaces and never on EF, so a deployment on Dapper, a
document store, or an existing schema you do not control can implement them instead and register
those in place of `AddToamaisutaaEntityFrameworkStores`.

| Interface | Holds |
|---|---|
| `IUserStore` | The local user row, and the read-or-create on first sight of a subject |
| `IExternalLoginStore` | One (provider, subject) pair per external identity |
| `IPasswordCredentialStore` | The local credential, and the wrong-code and current-password counters |
| `ISignInThrottleStore` | Wrong passwords at sign-in, per account and source |
| `IRefreshTokenStore` | Refresh tokens, hashed, grouped into families |
| `IPasswordResetTokenStore` | Single-use reset tokens, hashed |
| `IInvitationTokenStore` | Single-use invitation tokens, hashed |
| `IEmailVerificationTokenStore` | Single-use email verification tokens, hashed, each naming the address it proves |
| `ITwoFactorStore` | One TOTP enrolment per user |
| `IRecoveryCodeStore` | Hashed single-use recovery codes |
| `ITwoFactorChallengeStore` | Half-finished sign-ins |
| `ITrustedDeviceStore` | Trusted device families |
| `IMagicLinkTokenStore` | Single-use magic-link tokens, hashed |
| `IPasskeyCredentialStore` | Registered passkeys, one row per credential |
| `IPasskeyChallengeStore` | Outstanding passkey registration and assertion challenges |

An `IPasswordCredentialStore` of your own should write only what changed and throw
`CredentialConcurrencyException` when the row moved since it was read, the way the EF store does
with concurrency tokens. The flows catch it, read the row again and reapply their change. A store
that writes the whole row blindly still works, but parallel wrong passwords then all write the same
count and the lockout never arrives.

`IRefreshTokenStore.MarkRotatedAsync` and `ITrustedDeviceStore.MarkRotatedAsync` return whether
this call is the one that moved the row from live to rotated. Make it a single conditional write -
`WHERE Id = @id AND RotatedAt IS NULL AND RevokedAt IS NULL` - and return whether a row changed.
Returning true unconditionally lets two requests exchange one token at once, forking the session or
the device trust with no reuse ever detected.

Every `MarkConsumedAsync` - reset, magic-link, invitation and email-verification tokens, recovery
codes, two-factor and passkey challenges - follows the same rule: one write conditional on
`ConsumedAt IS NULL`, returning whether it spent the row. The flows act on nothing until it says
true, which is what makes single use hold when the same link or code arrives twice at once.

`ITwoFactorStore.RecordUsedStepAsync` is the TOTP version of the same thing: write the step only
where the stored one is null or lower, and return whether a row changed. That makes one code good
for one request, and stops a late write moving the step backwards.

`ISignInThrottleStore.UpdateFailedAttemptsAsync` follows the same rule, and inserts the row when the
expected count is zero and there is none yet. Key the table on (user, source), so two first failures
from one source collide rather than each inserting a row that counts one.

The overload of `ITwoFactorStore.UpdateFailedAttemptsAsync` taking `lockoutStrikes` writes it with the
count. Its default drops the strikes, so a store of your own that does not implement it keeps every
lock at the first length.

`ITwoFactorStore.UpdateFailedAttemptsAsync` holds the wrong-code count for an account with no
password credential. Write it only where the stored count still equals the expected one, and return
whether a row changed; the flows re-read and retry, so parallel wrong codes each count.

Register whichever the features you use require - the startup checks name the missing one rather
than failing at the first request:

```csharp
builder.Services.AddScoped<IUserStore, YourUserStore>();
builder.Services.AddScoped<IRefreshTokenStore, YourRefreshTokenStore>();
```

Three things the EF implementations do that yours must also do, because `Core` relies on them:

- **Tokens are looked up by hash, never by value.** Every `FindByHashAsync` takes an unsalted
  SHA-256 of the token and expects an exact match.
- **Rotation and revocation are recorded, not deleted.** `MarkRotatedAsync` has to leave the row
  findable, because presenting an already-rotated token is the theft signal that revokes the family.
  A store that deletes on rotation turns a stolen-token detector into a silent no-op.
- **Instants are compared, so they must be range-queryable.** The EF stores keep them as Unix
  milliseconds for the reason below.

## The tables

| Table | Holds |
|---|---|
| `ToamaisutaaUsers` | The local user: display name, email, avatar, timestamps |
| `ToamaisutaaExternalLogins` | One (provider, subject) pair per external identity, unique |
| `ToamaisutaaPasswordCredentials` | The local credential, one per user at most |
| `ToamaisutaaSignInThrottles` | Wrong passwords at sign-in per (user, source). The source is a hash, never an address |
| `ToamaisutaaRefreshTokens` | Issued refresh tokens, hashed, grouped into families |
| `ToamaisutaaPasswordResetTokens` | Single-use reset tokens, hashed |
| `ToamaisutaaInvitationTokens` | Single-use invitation tokens, hashed |
| `ToamaisutaaEmailVerificationTokens` | Single-use email verification tokens, hashed, each naming the address it proves |
| `ToamaisutaaMagicLinkTokens` | Single-use emailed sign-in tokens, hashed |
| `ToamaisutaaUserTwoFactors` | One TOTP enrolment per user, its secret encrypted at rest |
| `ToamaisutaaRecoveryCodes` | Hashed single-use recovery codes |
| `ToamaisutaaTwoFactorChallenges` | Half-finished sign-ins waiting on a second factor |
| `ToamaisutaaPasskeyCredentials` | Registered WebAuthn credentials, their public keys and signature counters |
| `ToamaisutaaPasskeyChallenges` | WebAuthn ceremonies in flight, with the options that were sent |

Credentials live in their own table rather than as columns on the user, because
`ToamaisutaaUsers.Email` is a profile field that OIDC provisioning rewrites whenever the token's
claim changes, and a login identifier must not move with it.

`ToamaisutaaUsers.Email` is therefore **not unique, permanently**. The model is multi-provider: one
person with accounts at two identity providers is two rows, legitimately sharing an address.

## When the profile is written

`ProfileSyncMode` decides how often the stored row is refreshed from the token's claims:

| Mode | Behaviour |
|---|---|
| `Never` | Write the profile once, at creation |
| `FirstSignInOnly` | The same, for when "only at creation" is the intent rather than the side effect |
| `OnChange` | **Default.** Write only when a mapped claim actually differs |
| `EveryRequest` | Write on every request |

`OnChange` avoids a write per request. It also handles the first-sign-in race: two concurrent requests for a never-seen subject both try to create, the unique index rejects one, and
it re-reads rather than throwing.

## Timestamps

Every instant is stored as Unix milliseconds in a signed integer column, not a provider-native
timestamp, because SQLite cannot range-query a `DateTimeOffset`. Two things change on a round trip,
both on purpose:

- **The offset is discarded and the instant is kept.** `12:00+02:00` reads back as `10:00+00:00` -
  the same moment, described from UTC.
- **The resolution is milliseconds.** `.1683914` reads back as `.168`.
