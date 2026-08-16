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
    modelBuilder.ApplyToamaisutaaConfiguration();
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
[Pomelo](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql). That is not a
judgement about either: Pomelo has no EF Core 10 release, and its latest version pins
`Microsoft.EntityFrameworkCore.Relational` to `[9.0.0, 9.0.999]`, so it cannot coexist with the rest
of this package. If Pomelo ships for EF Core 10 and you would rather use it, the swap is a provider
package and a regenerated migration - nothing in the schema changes.

## Not using Entity Framework at all

`Toamaisutaa.EntityFrameworkCore` is one implementation of a set of interfaces, not the storage
layer. `Toamaisutaa.Core` depends on the interfaces and never on EF, so a deployment on Dapper, a
document store, or an existing schema you do not control can implement them instead and register
those in place of `AddToamaisutaaEntityFrameworkStores`.

| Interface | Holds |
|---|---|
| `IUserStore` | The local user row, and the read-or-create on first sight of a subject |
| `IExternalLoginStore` | One (provider, subject) pair per external identity |
| `IPasswordCredentialStore` | The local credential, and the lockout counters |
| `IRefreshTokenStore` | Refresh tokens, hashed, grouped into families |
| `IPasswordResetTokenStore` | Single-use reset tokens, hashed |
| `IInvitationTokenStore` | Single-use invitation tokens, hashed |
| `ITwoFactorStore` | One TOTP enrolment per user |
| `IRecoveryCodeStore` | Hashed single-use recovery codes |
| `ITwoFactorChallengeStore` | Half-finished sign-ins |
| `ITrustedDeviceStore` | Trusted device families |

Register whichever the features you use require - the startup checks name the missing one rather
than failing at the first request:

```csharp
builder.Services.AddScoped<IUserStore, YourUserStore>();
builder.Services.AddScoped<IRefreshTokenStore, YourRefreshTokenStore>();
```

::: warning Breaking: `IUserStore` gained `SetUserNameAsync`
[Completing a reserved invitation](/provisioning-accounts#completing-a-reserved-invitation) sets a
user name on a row that was created with only an email, and no existing method could write it. A
custom `IUserStore` needs the new member before it compiles against this version.
:::

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
| `ToamaisutaaRefreshTokens` | Issued refresh tokens, hashed, grouped into families |
| `ToamaisutaaPasswordResetTokens` | Single-use reset tokens, hashed |
| `ToamaisutaaInvitationTokens` | Single-use invitation tokens, hashed |
| `ToamaisutaaUserTwoFactors` | One TOTP enrolment per user, its secret encrypted at rest |
| `ToamaisutaaRecoveryCodes` | Hashed single-use recovery codes |
| `ToamaisutaaTwoFactorChallenges` | Half-finished sign-ins waiting on a second factor |

Credentials live in their own table rather than as columns on the user, and the reason is worth
knowing: `ToamaisutaaUsers.Email` is a profile field that OIDC provisioning rewrites whenever the
token's claim changes. If that same column were the unique local-login identifier, an administrator
editing an email in your directory would silently change what someone types into your login form -
and a collision would throw out of an unrelated request. A login identifier and a profile field have
different rules.

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

`OnChange` exists because the obvious implementation - refresh the row on every authenticated
request - costs a write per request forever. It also handles the first-sign-in race: two concurrent
requests for a never-seen subject both try to create, the unique index rejects one, and it re-reads
rather than throwing.

## Timestamps

Every instant is stored as Unix milliseconds in a signed integer column, not a provider-native
timestamp. SQLite has no timestamp type, so EF keeps a `DateTimeOffset` as text and then declines to
translate `<` or `>` on it - correctly, since values written with different offsets do not sort right
as strings. An integer sorts identically on both providers and can be range-queried on both.

Two things change on a round trip, both on purpose:

- **The offset is discarded and the instant is kept.** `12:00+02:00` reads back as `10:00+00:00` -
  the same moment, described from UTC.
- **The resolution is milliseconds.** `.1683914` reads back as `.168`.

Both are right for audit timestamps, and both are visible enough that someone will notice.
