# Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer

SQL Server migrations for the [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) schema.
Migrations are provider-specific and cannot share an assembly, so each provider ships its own.

Install it alongside `Toamaisutaa.EntityFrameworkCore` and name it as the migrations assembly. The
SQL Server provider comes with it.

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlServer(
    connectionString,
    sqlServer => sqlServer.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer")));
```

[Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)
