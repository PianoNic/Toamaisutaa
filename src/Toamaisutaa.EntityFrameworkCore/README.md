# Toamaisutaa.EntityFrameworkCore

Entity Framework Core storage for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa): users,
external logins, password credentials, refresh tokens, reset tokens, and two-factor enrolments.

There are two ways to use it, and they differ only in whose `DbContext` holds the tables.

**Its own context**, so the tables live apart from yours:

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(
    connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
```

**Your context**, so they do not:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder) =>
    modelBuilder.ApplyToamaisutaaConfiguration();
```

```csharp
builder.Services.AddToamaisutaaEntityFrameworkStores<YourDbContext>();
```

The shipped migrations only cover `ToamaisutaaDbContext`, so with your own context you generate the
migration in your own project. Every entity configuration is public, and calling `ToTable` after one
renames its table.

## Migrations

Install one alongside this package - they are provider-specific and cannot share an assembly:

| Provider | Package |
|---|---|
| PostgreSQL | `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` |
| SQLite | `Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite` |
| SQL Server | `Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer` |
| MySQL | `Toamaisutaa.EntityFrameworkCore.Migrations.MySql` |

## One thing worth knowing

Every timestamp is stored as **Unix milliseconds in a `long`**, not as a native date type. SQLite
cannot translate a range query on a `DateTimeOffset`, and the cleanup sweep is exactly that query, so
the column type is chosen by the provider that cannot do it rather than the ones that can. The
conversion is transparent - the entities expose `DateTimeOffset` - but it is visible if you query the
tables by hand.

## Documentation

**[Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
