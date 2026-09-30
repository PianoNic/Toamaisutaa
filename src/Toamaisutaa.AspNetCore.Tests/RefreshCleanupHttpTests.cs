using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The cleanup sweep and reuse detection, which works from the very rows the sweep deletes.
/// </summary>
public class RefreshCleanupHttpTests
{
    /// <summary>
    /// A family kept alive by refreshing past its first token's fourteen days. The sweep used to
    /// delete that first token at its own expiry, so when a thief replayed it the answer was a plain
    /// unknown token - no revocation - and the family they were racing lived on.
    /// </summary>
    [Test]
    public async Task A_rotated_token_swept_after_its_own_expiry_still_trips_reuse_detection()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var first = await (await account.LoginAsync()).Json();
        var stolen = first.String("refresh_token")!;
        var current = stolen;

        // Each one checked: a refused refresh left current null, every later one 401, and the final
        // assertion then passed without reuse detection having had anything to do with it.
        for (var day = 0; day < 20; day++)
        {
            app.Time.Advance(TimeSpan.FromDays(1));
            var response = await app.Client.PostJson("/auth/refresh", new { refreshToken = current });
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
            current = (await response.Json()).String("refresh_token")!;
        }

        var sweep = new TokenCleanupService(
            app.Services.GetRequiredService<IServiceScopeFactory>(),
            app.Services.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>(),
            app.Time,
            NullLogger<TokenCleanupService>.Instance);

        await sweep.CleanupAsync(CancellationToken.None);

        // Still alive after the sweep, so what ends it below is the replay and nothing else.
        var beforeReplay = await app.Client.PostJson("/auth/refresh", new { refreshToken = current });
        await Assert.That(beforeReplay.StatusCode).IsEqualTo(HttpStatusCode.OK);
        current = (await beforeReplay.Json()).String("refresh_token")!;

        // The thief replays the first token, three weeks on.
        await app.Client.PostJson("/auth/refresh", new { refreshToken = stolen });

        // Reuse was detected, so the family is gone - including the owner's live token.
        var owner = await app.Client.PostJson("/auth/refresh", new { refreshToken = current });
        await Assert.That(owner.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }
}
