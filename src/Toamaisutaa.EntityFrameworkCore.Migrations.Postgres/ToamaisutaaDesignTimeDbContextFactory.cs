using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build a model without a host; the connection string is
/// never opened. Public because the EF tools reflect over it.
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
