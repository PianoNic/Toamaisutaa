using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An OpenID Connect subject is case-sensitive. The default collations on SQL Server and MySQL are
/// not, and MySQL's ignores accents as well, so the database alone would hand <c>Alice</c> the row
/// that belongs to <c>alice</c>.
/// </summary>
/// <remarks>
/// SQLite compares exactly by default, which is why the suite never saw this. The context here gives
/// the subject column SQLite's own case-insensitive collation, so the real store runs against a real
/// database that compares the way those two do.
/// </remarks>
public class ExternalSubjectCaseTests
{
    [Test]
    public async Task A_subject_differing_only_in_case_finds_nobody()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection()
            .AddDbContext<CaseInsensitiveContext>(options => options.UseSqlite(connection))
            .AddToamaisutaaEntityFrameworkStores<CaseInsensitiveContext>()
            .BuildServiceProvider();

        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<CaseInsensitiveContext>().Database.EnsureCreatedAsync();

        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
        var logins = scope.ServiceProvider.GetRequiredService<IExternalLoginStore>();

        var profile = new ExternalUserProfile { Subject = "alice" };
        var alice = await users.CreateAsync(profile);
        await logins.LinkAsync(alice.Id, ToamaisutaaDefaults.ProviderKey, profile);

        await Assert.That(await logins.FindAsync(ToamaisutaaDefaults.ProviderKey, "alice")).IsNotNull();
        await Assert.That(await logins.FindAsync(ToamaisutaaDefaults.ProviderKey, "ALICE")).IsNull();
    }

    /// <summary>
    /// The lookup above is right, which sends <c>ALICE</c> down the create path - into a unique index
    /// that says <c>alice</c> is the same subject. The retry met the same index, and the conflict
    /// escaped as a 500 naming nothing. Refused with the reason instead, because only a collation
    /// change fixes it.
    /// </summary>
    [Test]
    public async Task Provisioning_a_subject_the_database_folds_into_another_says_why()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection()
            .AddDbContext<CaseInsensitiveContext>(options => options.UseSqlite(connection))
            .AddToamaisutaaEntityFrameworkStores<CaseInsensitiveContext>()
            .BuildServiceProvider();

        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<CaseInsensitiveContext>().Database.EnsureCreatedAsync();

        var options = Microsoft.Extensions.Options.Options.Create(new ToamaisutaaProvisioningOptions());
        var provisioner = new Toamaisutaa.Core.ExternalLoginProvisioner(
            new Toamaisutaa.Core.DefaultClaimsProfileMapper(options),
            new Toamaisutaa.Core.DefaultProvisioningPolicy(),
            scope.ServiceProvider.GetRequiredService<IUserStore>(),
            scope.ServiceProvider.GetRequiredService<IExternalLoginStore>(),
            options,
            Microsoft.Extensions.Options.Options.Create(new ToamaisutaaLocalLoginOptions()),
            TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<Toamaisutaa.Core.ExternalLoginProvisioner>.Instance);

        static System.Security.Claims.ClaimsPrincipal Subject(string subject) =>
            new(new System.Security.Claims.ClaimsIdentity([new System.Security.Claims.Claim("sub", subject)], "test"));

        await provisioner.ProvisionAsync(Subject("alice"));

        var refused = await Assert.That(async () => await provisioner.ProvisionAsync(Subject("ALICE"))).Throws<InvalidOperationException>();

        await Assert.That(refused!.Message).Contains("collation");
    }

    private sealed class CaseInsensitiveContext(DbContextOptions<CaseInsensitiveContext> options) : ToamaisutaaDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<ToamaisutaaExternalLogin>().Property(login => login.Subject).UseCollation("NOCASE");
            modelBuilder.Entity<ToamaisutaaExternalLogin>().Property(login => login.ProviderKey).UseCollation("NOCASE");
        }
    }
}
