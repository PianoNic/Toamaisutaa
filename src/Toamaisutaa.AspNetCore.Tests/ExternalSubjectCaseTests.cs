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
