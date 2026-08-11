# Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite

SQLite migrations for the [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) schema. Migrations
are provider-specific and cannot share an assembly, so each provider ships its own.

Install it alongside `Toamaisutaa.EntityFrameworkCore` and name it as the migrations assembly. The
SQLite provider comes with it.

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(
    connectionString,
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
```

[Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)
