using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

public class RefreshCleanupHttpTests
{
    /// <summary>
    /// Reuse detection works from the rows the sweep deletes, so a swept rotated token must still revoke its live family.
    /// </summary>
    [Test]
    public async Task A_rotated_token_swept_after_its_own_expiry_still_trips_reuse_detection()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var first = await (await account.LoginAsync()).Json();
        var stolen = first.String("refresh_token")!;
        var current = stolen;

        // Each refresh is asserted, or a refused one would make the final 401 pass without reuse detection.
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

        // Proves the family survives the sweep, so only the replay can end it.
        var beforeReplay = await app.Client.PostJson("/auth/refresh", new { refreshToken = current });
        await Assert.That(beforeReplay.StatusCode).IsEqualTo(HttpStatusCode.OK);
        current = (await beforeReplay.Json()).String("refresh_token")!;

        await app.Client.PostJson("/auth/refresh", new { refreshToken = stolen });

        var owner = await app.Client.PostJson("/auth/refresh", new { refreshToken = current });
        await Assert.That(owner.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }
}
