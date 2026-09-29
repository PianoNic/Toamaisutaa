using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// One refresh token presented twice at once - the thief and the owner, racing.
/// </summary>
public class ConcurrentRefreshHttpTests
{
    /// <summary>
    /// Rotation read the row, saw it live, then marked it spent. Two requests between those steps
    /// both saw it live and both got a new pair, forking the family with no reuse ever detected.
    /// </summary>
    [Test]
    public async Task A_refresh_token_presented_in_parallel_is_exchanged_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var signedIn = await (await account.LoginAsync()).Json();
        var refreshToken = signedIn.String("refresh_token");

        var attempts = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            app.Client.PostJson("/auth/refresh", new { refreshToken })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }
}
