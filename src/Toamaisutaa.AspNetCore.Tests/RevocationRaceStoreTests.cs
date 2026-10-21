using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A rotation that inserts its new token while a revocation of the same family is running. On
/// PostgreSQL the revoking UPDATE never sees a row inserted after it started, and the rotation's check
/// of its parent does not see the uncommitted revocation, so the new token stayed live. SQLite
/// serialises writers, so the interleaving is made here by inserting right after the first UPDATE.
/// </summary>
public class RevocationRaceStoreTests
{
    [Test]
    [Arguments("family")]
    [Arguments("user")]
    public async Task A_token_inserted_while_its_family_is_revoked_is_revoked_too(string scope)
    {
        var path = Path.Combine(Path.GetTempPath(), $"toamaisutaa-revocation-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString();
        var interceptor = new InsertAfterFirstRevoke();

        await using var services = new ServiceCollection()
            .AddToamaisutaaDbContext(options => options.UseSqlite(connectionString).AddInterceptors(interceptor))
            .BuildServiceProvider();

        interceptor.Scopes = services.GetRequiredService<IServiceScopeFactory>();

        await using (var setup = services.CreateAsyncScope())
        {
            await setup.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.EnsureCreatedAsync();
        }

        await using var work = services.CreateAsyncScope();
        var user = await work.ServiceProvider.GetRequiredService<IUserStore>().CreateAsync(new ExternalUserProfile { Subject = "ada" });
        var tokens = work.ServiceProvider.GetRequiredService<IRefreshTokenStore>();

        var parent = Token(user.Id, Guid.NewGuid(), "parent");
        await tokens.CreateAsync(parent);

        var child = Token(user.Id, parent.FamilyId, "child");
        interceptor.Table = "ToamaisutaaRefreshTokens";
        interceptor.Insert = other => other.GetRequiredService<IRefreshTokenStore>().CreateAsync(child);

        if (scope == "family")
            await tokens.RevokeFamilyAsync(parent.FamilyId, "revoked-by-user", DateTimeOffset.UtcNow);
        else
            await tokens.RevokeAllForUserAsync(user.Id, "revoked-by-user", DateTimeOffset.UtcNow);

        await Assert.That(interceptor.Inserted).IsTrue();

        await using var check = services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<IRefreshTokenStore>().FindByHashAsync("child");

        // HasValue, not IsNotNull: TUnit's IsNotNull passes a null DateTimeOffset?.
        await Assert.That(stored!.RevokedAt.HasValue).IsTrue();
    }

    /// <summary>
    /// The same race for a trusted device, whose store revoked in one UPDATE after the refresh store
    /// had learned to repeat it. A device rotated during "revoke all my devices" stayed trusted.
    /// </summary>
    [Test]
    [Arguments("family")]
    [Arguments("user")]
    public async Task A_device_inserted_while_its_family_is_revoked_is_revoked_too(string scope)
    {
        var path = Path.Combine(Path.GetTempPath(), $"toamaisutaa-revocation-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString();
        var interceptor = new InsertAfterFirstRevoke();

        await using var services = new ServiceCollection()
            .AddToamaisutaaDbContext(options => options.UseSqlite(connectionString).AddInterceptors(interceptor))
            .BuildServiceProvider();

        interceptor.Scopes = services.GetRequiredService<IServiceScopeFactory>();

        await using (var setup = services.CreateAsyncScope())
        {
            await setup.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.EnsureCreatedAsync();
        }

        await using var work = services.CreateAsyncScope();
        var user = await work.ServiceProvider.GetRequiredService<IUserStore>().CreateAsync(new ExternalUserProfile { Subject = "ada" });
        var devices = work.ServiceProvider.GetRequiredService<ITrustedDeviceStore>();

        var parent = Device(user.Id, Guid.NewGuid(), "parent");
        await devices.CreateAsync(parent);

        var child = Device(user.Id, parent.FamilyId, "child");
        interceptor.Table = "ToamaisutaaTrustedDevices";
        interceptor.Insert = other => other.GetRequiredService<ITrustedDeviceStore>().CreateAsync(child);

        if (scope == "family")
            await devices.RevokeFamilyAsync(parent.FamilyId, "revoked-by-user", DateTimeOffset.UtcNow);
        else
            await devices.RevokeAllForUserAsync(user.Id, "revoked-by-user", DateTimeOffset.UtcNow);

        await Assert.That(interceptor.Inserted).IsTrue();

        await using var check = services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<ITrustedDeviceStore>().FindByHashAsync("child");

        await Assert.That(stored!.RevokedAt.HasValue).IsTrue();
    }

    private static ToamaisutaaTrustedDevice Device(Guid userId, Guid familyId, string hash)
    {
        var now = DateTimeOffset.UtcNow;

        return new ToamaisutaaTrustedDevice
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FamilyId = familyId,
            TokenHash = hash,
            SecurityStamp = "stamp",
            SecondFactorAt = now,
            CreatedAt = now,
            FamilyStartedAt = now,
            ExpiresAt = now.AddDays(30),
            LastUsedAt = now,
        };
    }

    private static ToamaisutaaRefreshToken Token(Guid userId, Guid familyId, string hash)
    {
        var now = DateTimeOffset.UtcNow;

        return new ToamaisutaaRefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FamilyId = familyId,
            TokenHash = hash,
            CreatedAt = now,
            ExpiresAt = now.AddDays(14),
            FamilyStartedAt = now,
            SecurityStamp = "stamp",
            LastUsedAt = now,
        };
    }

    /// <summary>Runs <see cref="Insert"/> the moment the first revoking UPDATE on <see cref="Table"/>
    /// has run - the rotation that commits after the revocation's snapshot was taken.</summary>
    private sealed class InsertAfterFirstRevoke : DbCommandInterceptor
    {
        internal IServiceScopeFactory Scopes { get; set; } = null!;

        internal string? Table { get; set; }

        internal Func<IServiceProvider, Task>? Insert { get; set; }

        internal bool Inserted { get; private set; }

        public override async ValueTask<int> NonQueryExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (Insert is { } insert
                && Table is { } table
                && !Inserted
                && command.CommandText.Contains("UPDATE", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains(table, StringComparison.Ordinal))
            {
                Inserted = true;

                await using var other = Scopes.CreateAsyncScope();
                await insert(other.ServiceProvider);
            }

            return result;
        }
    }
}
