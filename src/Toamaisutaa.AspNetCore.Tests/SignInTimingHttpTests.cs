using System.Diagnostics;
using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A refused sign-in answers one body whatever the reason. It has to answer at one time too, or the
/// clock says what the body will not.
/// </summary>
public class SignInTimingHttpTests
{
    // Far above anything a refusal takes on its own, even with the whole suite running beside it.
    // At 600ms a loaded machine could take that long without any floor, and the test went green with
    // the delay deleted.
    private static readonly TimeSpan Floor = TimeSpan.FromSeconds(5);

    /// <summary>
    /// An unknown name answered after one lookup and a dummy hash; a real one also wrote its failure
    /// count, and an old hash on a slower algorithm took longer still. Only a lower bound is asserted:
    /// an upper one would be a test of how busy the machine is.
    /// </summary>
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

    /// <summary>A successful sign-in has nothing to hide, and is not made to wait.</summary>
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
