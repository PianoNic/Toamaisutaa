using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql;

/// <summary>
/// Exists so <c>dotnet ef migrations add</c> can build a model without a host. The connection
/// string is never opened: generating a migration only needs the provider, and the deployed
/// application supplies its own. Public because the EF tools reflect over it.
/// </summary>
public sealed class ToamaisutaaDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ToamaisutaaDbContext>
{
    internal const string MigrationsAssembly = "Toamaisutaa.EntityFrameworkCore.Migrations.MySql";

    public ToamaisutaaDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ToamaisutaaDbContext>()
            .UseMySQL(
                "Server=localhost;Port=3306;Database=toamaisutaa;User Id=root;Password=design_time_only",
                mySql => mySql.MigrationsAssembly(MigrationsAssembly))
            .Options;

        return new ToamaisutaaDbContext(options);
    }
}
