using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>SQLite compares exactly by default, so the context here uses NOCASE to compare the way the
/// SQL Server and MySQL default collations do.</summary>
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

    [Test]
    public async Task Provisioning_a_subject_the_database_folds_into_another_says_why()
    {
        var refused = await RefusalAsync<CaseInsensitiveContext>("alice", "ALICE");

        await Assert.That(refused.Message).Contains("collation");
    }

    /// <summary>
    /// SQL Server pads trailing spaces under every collation, BIN2 included, so the refusal blamed case
    /// or accents for subjects that differ in neither. SQLite's RTRIM compares the same way.
    /// </summary>
    [Test]
    public async Task Provisioning_a_subject_that_differs_by_trailing_spaces_says_so()
    {
        var refused = await RefusalAsync<TrailingSpaceContext>("u1", "u1 ");

        await Assert.That(refused.Message).Contains("trailing spaces");
    }

    private static async Task<InvalidOperationException> RefusalAsync<TContext>(string first, string second)
        where TContext : ToamaisutaaDbContext
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection()
            .AddDbContext<TContext>(options => options.UseSqlite(connection))
            .AddToamaisutaaEntityFrameworkStores<TContext>()
            .BuildServiceProvider();

        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<TContext>().Database.EnsureCreatedAsync();

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

        await provisioner.ProvisionAsync(Subject(first));

        return (await Assert.That(async () => await provisioner.ProvisionAsync(Subject(second))).Throws<InvalidOperationException>())!;
    }

    [Test]
    [Arguments("sqlserver", "Latin1_General_100_BIN2")]
    [Arguments("mysql", "utf8mb4_bin")]
    [Arguments("sqlite", null)]
    public async Task Subjects_compare_exactly_on_every_provider(string provider, string? collation)
    {
        var builder = new DbContextOptionsBuilder<ToamaisutaaDbContext>();

        _ = provider switch
        {
            "sqlserver" => builder.UseSqlServer("Server=unused;Database=unused"),
            "mysql" => builder.UseMySQL("Server=unused;Database=unused"),
            _ => builder.UseSqlite("DataSource=:memory:"),
        };

        await using var context = new ToamaisutaaDbContext(builder.Options);
        // The design-time model: the runtime one drops what only a migration needs, collation included.
        var model = context.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model;
        var subject = model.FindEntityType(typeof(ToamaisutaaExternalLogin))!.FindProperty(nameof(ToamaisutaaExternalLogin.Subject))!;

        await Assert.That(subject.GetCollation()).IsEqualTo(collation);
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

    private sealed class TrailingSpaceContext(DbContextOptions<TrailingSpaceContext> options) : ToamaisutaaDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<ToamaisutaaExternalLogin>().Property(login => login.Subject).UseCollation("RTRIM");
        }
    }
}
