# Storage and migrations

Provisioning is opt-in. The package is fully usable with no local user table at all - which is what
three of the four applications it was extracted from actually do, letting the identity provider own
every user.

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
afterwards to rename anything. Generate the migration in your own project - the two migration
packages only cover `ToamaisutaaDbContext`.

## Why migrations ship as separate packages

EF Core cannot hold two providers' migration sets and model snapshots in one assembly. So each
provider gets its own package, and the consumer names it:

```csharp
npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")
sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")
```

Postgres and SQLite ship today. SQL Server would be a third package, not a change to these two.

## The tables

| Table | Holds |
|---|---|
| `ToamaisutaaUsers` | The local user: display name, email, avatar, timestamps |
| `ToamaisutaaExternalLogins` | One (provider, subject) pair per external identity, unique |
| `ToamaisutaaPasswordCredentials` | The local credential, one per user at most |
| `ToamaisutaaRefreshTokens` | Issued refresh tokens, hashed, grouped into families |
| `ToamaisutaaPasswordResetTokens` | Single-use reset tokens, hashed |

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
| `FirstSignInOnly` | The same, kept distinct so the intent reads correctly |
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
