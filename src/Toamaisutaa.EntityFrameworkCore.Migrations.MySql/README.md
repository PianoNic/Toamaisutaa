# Toamaisutaa.EntityFrameworkCore.Migrations.MySql

MySQL migrations for the [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) schema. Migrations
are provider-specific and cannot share an assembly, so each provider ships its own.

Install it alongside `Toamaisutaa.EntityFrameworkCore` and name it as the migrations assembly. The
`MySql.EntityFrameworkCore` provider comes with it.

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseMySQL(
    connectionString,
    mySql => mySql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.MySql")));
```

[Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)
