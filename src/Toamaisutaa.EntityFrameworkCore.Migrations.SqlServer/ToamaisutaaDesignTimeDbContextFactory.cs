using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build a model without a host; the connection string is
/// never opened. Public because the EF tools reflect over it.
/// </summary>
public sealed class ToamaisutaaDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ToamaisutaaDbContext>
{
    internal const string MigrationsAssembly = "Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer";

    public ToamaisutaaDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ToamaisutaaDbContext>()
            .UseSqlServer(
                "Server=localhost;Database=toamaisutaa;User Id=sa;Password=Design_time_only_1;TrustServerCertificate=True",
                sqlServer => sqlServer.MigrationsAssembly(MigrationsAssembly))
            .Options;

        return new ToamaisutaaDbContext(options);
    }
}
