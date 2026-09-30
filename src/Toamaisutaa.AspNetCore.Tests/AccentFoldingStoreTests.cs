using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// MySQL's default collation ignores accents, so an address like VÍCTIM@ matched VICTIM@'s row. SQLite
/// has no such collation, so one is registered on the connection that compares the way MySQL does.
/// </summary>
public class AccentFoldingStoreTests
{
    private const string Plain = "VICTIM@EXAMPLE.COM";
    private const string Accented = "VÍCTIM@EXAMPLE.COM";

    [Test]
    public async Task An_accented_address_does_not_find_the_plain_addresses_invitation()
    {
        await using var fixture = await Fixture.StartAsync();
        var invitations = fixture.Scope.ServiceProvider.GetRequiredService<IInvitationTokenStore>();
        var user = await fixture.Scope.ServiceProvider.GetRequiredService<IUserStore>().CreateAsync(new ExternalUserProfile { Subject = "invited" });

        await invitations.CreateAsync(new ToamaisutaaInvitationToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = "invitation",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            Email = "victim@example.com",
            NormalizedEmail = Plain,
        });

        await Assert.That(await invitations.FindOpenByEmailAsync(Plain, DateTimeOffset.UtcNow)).IsNotNull();
        await Assert.That(await invitations.FindOpenByEmailAsync(Accented, DateTimeOffset.UtcNow)).IsNull();
    }

    [Test]
    public async Task An_accented_identifier_does_not_find_the_plain_addresses_credential()
    {
        await using var fixture = await Fixture.StartAsync();
        var credentials = fixture.Scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
        var user = await fixture.Scope.ServiceProvider.GetRequiredService<IUserStore>().CreateAsync(new ExternalUserProfile { Subject = "victim" });

        await credentials.CreateAsync(new ToamaisutaaPasswordCredential
        {
            UserId = user.Id,
            UserName = "victim",
            NormalizedUserName = "VICTIM",
            Email = "victim@example.com",
            NormalizedEmail = Plain,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        await Assert.That(await credentials.FindByIdentifierAsync(Plain)).IsNotNull();
        await Assert.That(await credentials.FindByIdentifierAsync(Accented)).IsNull();
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly ServiceProvider _services;

        private Fixture(SqliteConnection connection, ServiceProvider services, AsyncServiceScope scope)
        {
            _connection = connection;
            _services = services;
            Scope = scope;
        }

        internal AsyncServiceScope Scope { get; }

        internal static async Task<Fixture> StartAsync()
        {
            var connection = new SqliteConnection("DataSource=:memory:");
            await connection.OpenAsync();

            var compare = CultureInfo.InvariantCulture.CompareInfo;
            connection.CreateCollation("ACCENTS", (left, right) =>
                compare.Compare(left, right, CompareOptions.IgnoreNonSpace | CompareOptions.IgnoreCase));

            var services = new ServiceCollection()
                .AddDbContext<AccentFoldingContext>(options => options.UseSqlite(connection))
                .AddToamaisutaaEntityFrameworkStores<AccentFoldingContext>()
                .BuildServiceProvider();

            var scope = services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccentFoldingContext>().Database.EnsureCreatedAsync();

            return new Fixture(connection, services, scope);
        }

        public async ValueTask DisposeAsync()
        {
            await Scope.DisposeAsync();
            await _services.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class AccentFoldingContext(DbContextOptions<AccentFoldingContext> options) : ToamaisutaaDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<ToamaisutaaInvitationToken>().Property(token => token.NormalizedEmail).UseCollation("ACCENTS");
            modelBuilder.Entity<ToamaisutaaPasswordCredential>().Property(credential => credential.NormalizedEmail).UseCollation("ACCENTS");
            modelBuilder.Entity<ToamaisutaaPasswordCredential>().Property(credential => credential.NormalizedUserName).UseCollation("ACCENTS");
        }
    }
}
