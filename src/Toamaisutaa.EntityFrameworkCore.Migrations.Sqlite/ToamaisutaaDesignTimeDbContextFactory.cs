using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite;

/// <summary>
/// Exists so <c>dotnet ef migrations add</c> can build a model without a host. Public because the
/// EF tools reflect over it.
/// </summary>
public sealed class ToamaisutaaDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ToamaisutaaDbContext>
{
    internal const string MigrationsAssembly = "Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite";

    public ToamaisutaaDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ToamaisutaaDbContext>()
            .UseSqlite(
                "Data Source=toamaisutaa.db",
                sqlite => sqlite.MigrationsAssembly(MigrationsAssembly))
            .Options;

        return new ToamaisutaaDbContext(options);
    }
}
