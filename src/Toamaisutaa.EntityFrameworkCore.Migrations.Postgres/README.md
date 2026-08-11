# Toamaisutaa.EntityFrameworkCore.Migrations.Postgres

PostgreSQL migrations for the [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) schema.
Migrations are provider-specific and cannot share an assembly, so each provider ships its own.

Install it alongside `Toamaisutaa.EntityFrameworkCore` and name it as the migrations assembly. The
Npgsql provider comes with it.

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(
    connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
```

[Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)
