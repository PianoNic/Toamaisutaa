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

        interceptor.Child = Token(user.Id, parent.FamilyId, "child");

        if (scope == "family")
            await tokens.RevokeFamilyAsync(parent.FamilyId, "revoked-by-user", DateTimeOffset.UtcNow);
        else
            await tokens.RevokeAllForUserAsync(user.Id, "revoked-by-user", DateTimeOffset.UtcNow);

        await Assert.That(interceptor.Inserted).IsTrue();

        await using var check = services.CreateAsyncScope();
        var child = await check.ServiceProvider.GetRequiredService<IRefreshTokenStore>().FindByHashAsync("child");

        // HasValue, not IsNotNull: TUnit's IsNotNull passes a null DateTimeOffset?.
        await Assert.That(child!.RevokedAt.HasValue).IsTrue();
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

    /// <summary>Inserts <see cref="Child"/> the moment the first revoking UPDATE has run - the
    /// rotation that commits after the revocation's snapshot was taken.</summary>
    private sealed class InsertAfterFirstRevoke : DbCommandInterceptor
    {
        internal IServiceScopeFactory Scopes { get; set; } = null!;

        internal ToamaisutaaRefreshToken? Child { get; set; }

        internal bool Inserted { get; private set; }

        public override async ValueTask<int> NonQueryExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (Child is { } child
                && !Inserted
                && command.CommandText.Contains("UPDATE", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains("ToamaisutaaRefreshTokens", StringComparison.Ordinal))
            {
                Inserted = true;

                await using var other = Scopes.CreateAsyncScope();
                await other.ServiceProvider.GetRequiredService<IRefreshTokenStore>().CreateAsync(child, cancellationToken);
            }

            return result;
        }
    }
}
