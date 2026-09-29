using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A context whose default is no tracking, which plenty of applications set globally for their own
/// read-heavy queries. The credential store has to write through it all the same.
/// </summary>
/// <remarks>
/// Against real SQLite with the real stores. Under that default, a credential write went through
/// the branch for a detached instance, set values on a copy that was itself untracked, and saved
/// nothing - a password change or a lockout that returned success and never happened.
/// </remarks>
public class NoTrackingContextTests
{
    [Test]
    public async Task A_credential_write_lands_under_a_no_tracking_default()
    {
        await using var fixture = await Fixture.StartAsync();

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
            var credential = (await store.FindByUserIdAsync(fixture.UserId))!;

            credential.PasswordHash = "changed";
            credential.FailedAttemptCount = 3;
            await store.UpdateAsync(credential);
        }

        await using var check = fixture.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<IPasswordCredentialStore>().FindByUserIdAsync(fixture.UserId);

        await Assert.That(stored!.PasswordHash).IsEqualTo("changed");
        await Assert.That(stored.FailedAttemptCount).IsEqualTo(3);
    }

    /// <summary>The concurrency check has to hold under the same default, not only the write.</summary>
    [Test]
    public async Task A_stale_credential_write_is_refused_under_a_no_tracking_default()
    {
        await using var fixture = await Fixture.StartAsync();

        await using var stale = fixture.Services.CreateAsyncScope();
        await using var fresh = fixture.Services.CreateAsyncScope();

        var staleStore = stale.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
        var freshStore = fresh.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();

        var old = (await staleStore.FindByUserIdAsync(fixture.UserId))!;
        var current = (await freshStore.FindByUserIdAsync(fixture.UserId))!;

        current.PasswordHash = "reset-hash";
        await freshStore.UpdateAsync(current);

        old.FailedAttemptCount++;

        await Assert.That(async () => await staleStore.UpdateAsync(old)).Throws<CredentialConcurrencyException>();
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private Fixture(SqliteConnection connection, ServiceProvider services, Guid userId)
        {
            _connection = connection;
            Services = services;
            UserId = userId;
        }

        public ServiceProvider Services { get; }

        public Guid UserId { get; }

        public static async Task<Fixture> StartAsync()
        {
            var path = Path.Combine(Path.GetTempPath(), $"toamaisutaa-notracking-{Guid.NewGuid():N}.db");
            var connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString();

            var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync();

            var services = new ServiceCollection()
                .AddToamaisutaaDbContext(options => options
                    .UseSqlite(connectionString)
                    .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking))
                .BuildServiceProvider();

            await using var scope = services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.EnsureCreatedAsync();

            var user = await scope.ServiceProvider.GetRequiredService<IUserStore>().CreateAsync(new ExternalUserProfile { Subject = "ada" });

            await scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>().CreateAsync(new ToamaisutaaPasswordCredential
            {
                UserId = user.Id,
                UserName = "ada",
                NormalizedUserName = "ADA",
                PasswordHash = "original",
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });

            return new Fixture(connection, services, user.Id);
        }

        public async ValueTask DisposeAsync()
        {
            await Services.DisposeAsync();
            await _connection.DisposeAsync();
            SqliteConnection.ClearAllPools();
        }
    }
}
