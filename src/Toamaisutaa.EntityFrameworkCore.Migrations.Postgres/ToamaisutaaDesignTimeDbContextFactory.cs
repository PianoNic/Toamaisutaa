using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres;

/// <summary>
/// Exists so <c>dotnet ef migrations add</c> can build a model without a host. The connection
/// string is never opened: generating a migration only needs the provider, and the deployed
/// application supplies its own. Public because the EF tools reflect over it.
/// </summary>
public sealed class ToamaisutaaDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ToamaisutaaDbContext>
{
    internal const string MigrationsAssembly = "Toamaisutaa.EntityFrameworkCore.Migrations.Postgres";

    public ToamaisutaaDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ToamaisutaaDbContext>()
            .UseNpgsql(
                "Host=localhost;Database=toamaisutaa;Username=postgres;Password=postgres",
                npgsql => npgsql.MigrationsAssembly(MigrationsAssembly))
            .Options;

        return new ToamaisutaaDbContext(options);
    }
}
