using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build a model without a host; the connection string is
/// never opened. Public because the EF tools reflect over it.
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
