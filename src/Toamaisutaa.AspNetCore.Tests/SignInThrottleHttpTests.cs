using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Wrong passwords lock out where they came from, not the account's owner.</summary>
public class SignInThrottleHttpTests
{
    private const string Guesser = "203.0.113.7";
    private const string Owner = "198.51.100.20";

    [Test]
    public async Task Wrong_passwords_from_one_address_lock_that_address_and_not_the_owner_elsewhere()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await LoginAsync(app, account, "not the password", Guesser);

        await Assert.That((await LoginAsync(app, account, account.Password, Guesser)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_right_password_forgives_the_typos_its_own_address_made_before_it()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 4; i++)
            await LoginAsync(app, account, "not the password", Owner);

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        await LoginAsync(app, account, "not the password", Owner);

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>Parallel guesses each read the same count; a write that is not conditional on it counts
    /// several of them as one.</summary>
    [Test]
    public async Task Parallel_guesses_from_one_address_are_each_counted()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => LoginAsync(app, account, "not the password", Guesser)));

        await Assert.That((await LoginAsync(app, account, account.Password, Guesser)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Addresses_in_one_ipv6_64_count_as_one_source()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await LoginAsync(app, account, "not the password", $"2001:db8:0:1::{i + 1}");

        await Assert.That((await LoginAsync(app, account, account.Password, "2001:db8:0:1::99")).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await LoginAsync(app, account, account.Password, "2001:db8:0:2::1")).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Guessing_spread_across_addresses_reaches_the_account_wide_ceiling()
    {
        await using var app = await TestApp.StartAsync(configure: Ceiling(6));
        var account = await Account.RegisterAsync(app);

        foreach (var address in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" })
        {
            await LoginAsync(app, account, "not the password", address);
            await LoginAsync(app, account, "not the password", address);
        }

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_right_password_does_not_wipe_out_guesses_from_elsewhere()
    {
        await using var app = await TestApp.StartAsync(configure: Ceiling(6));
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 3; i++)
            await LoginAsync(app, account, "not the password", $"203.0.113.{i + 1}");

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        for (var i = 0; i < 3; i++)
            await LoginAsync(app, account, "not the password", $"203.0.113.{i + 10}");

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>An owner retrying while the ceiling stands did not guess, so their own address is not
    /// still locked once the ceiling lifts.</summary>
    [Test]
    public async Task Attempts_refused_by_the_ceiling_are_not_held_against_their_address()
    {
        await using var app = await TestApp.StartAsync(configure: Ceiling(6));
        var account = await Account.RegisterAsync(app);

        foreach (var address in new[] { "203.0.113.1", "203.0.113.2", "203.0.113.3" })
        {
            await LoginAsync(app, account, "not the password", address);
            await LoginAsync(app, account, "not the password", address);
        }

        app.Time.Advance(TimeSpan.FromMinutes(10));

        for (var i = 0; i < 5; i++)
            await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        app.Time.Advance(TimeSpan.FromMinutes(6));

        await Assert.That((await LoginAsync(app, account, account.Password, Owner)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>What keeps a teacher signing in when a pupil on the same school address has locked it.</summary>
    [Test]
    public async Task A_trusted_device_signs_in_past_a_locked_address_and_a_reached_ceiling()
    {
        await using var app = await TestApp.StartAsync(configure: Ceiling(6));
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        for (var i = 0; i < 5; i++)
            await LoginAsync(app, account, "not the password", Guesser);

        await LoginAsync(app, account, "not the password", "203.0.113.99");

        await Assert.That((await LoginAsync(app, account, account.Password, Guesser)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await LoginAsync(app, account, account.Password, Guesser, deviceToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>Otherwise a stolen device token would be an unlimited way to guess the password.</summary>
    [Test]
    public async Task A_trusted_device_has_a_budget_of_its_own()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        for (var i = 0; i < 5; i++)
            await LoginAsync(app, account, "not the password", Guesser, deviceToken);

        await Assert.That((await LoginAsync(app, account, account.Password, Owner, deviceToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await LoginAsync(app, account, account.Password, Guesser)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_source_lock_says_so_in_its_audit_event_and_the_ceiling_does_not()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(
            configure: Ceiling(6),
            configureServices: services =>
            {
                services.AddSingleton(recorded);
                services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
            });

        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await LoginAsync(app, account, "not the password", Guesser);

        await LoginAsync(app, account, "not the password", Owner);

        var locks = recorded.OfType<AccountLockedOut>().ToList();

        await Assert.That(locks.Count).IsEqualTo(2);
        await Assert.That(locks[0].SourceOnly).IsTrue();
        await Assert.That(locks[1].SourceOnly).IsFalse();
    }

    /// <summary>A custom store set without one would otherwise start clean and fail at the first sign-in.</summary>
    [Test]
    public async Task Startup_names_a_missing_throttle_store()
    {
        var started = async () =>
        {
            await using var app = await TestApp.StartAsync(configureServices: services =>
                services.RemoveAll<ISignInThrottleStore>());
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains(nameof(ISignInThrottleStore));
    }

    private static Action<Dictionary<string, string?>> Ceiling(int attempts) =>
        settings => settings["LocalLogin:MaxFailedAttemptsPerAccount"] = attempts.ToString();

    private static Task<HttpResponseMessage> LoginAsync(TestApp app, Account account, string password, string remoteIp, string? deviceToken = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { identifier = account.UserName, password, deviceToken }),
        };

        request.Headers.Add(TestApp.RemoteIpHeader, remoteIp);
        return app.Client.SendAsync(request);
    }

    private sealed class RecordingSink(List<AuthenticationEvent> recorded) : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
        {
            lock (recorded)
                recorded.Add(authenticationEvent);

            return Task.CompletedTask;
        }
    }
}
