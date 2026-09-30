using System.Diagnostics;
using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

public class SignInTimingHttpTests
{
    // Far above anything a refusal takes on its own under suite load, or the test passes with the delay deleted.
    private static readonly TimeSpan Floor = TimeSpan.FromSeconds(5);

    /// <summary>Only a lower bound is asserted: an upper one would test how busy the machine is.</summary>
    [Test]
    [Arguments("nobody-at-all", "whatever")]
    [Arguments("ada", "not the password")]
    public async Task A_refused_sign_in_takes_at_least_the_floor(string identifier, string password)
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
            settings["LocalLogin:SignInRefusalFloor"] = Floor.ToString());

        await Account.RegisterAsync(app);

        var started = Stopwatch.GetTimestamp();
        var response = await app.Client.PostJson("/auth/login", new { identifier, password });
        var elapsed = Stopwatch.GetElapsedTime(started);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(elapsed).IsGreaterThanOrEqualTo(Floor);
    }

    [Test]
    public async Task A_successful_sign_in_is_not_held_to_the_floor()
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
            settings["LocalLogin:SignInRefusalFloor"] = "00:00:30");

        var account = await Account.RegisterAsync(app);

        var started = Stopwatch.GetTimestamp();
        var response = await account.LoginAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(Stopwatch.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(30));
    }
}
