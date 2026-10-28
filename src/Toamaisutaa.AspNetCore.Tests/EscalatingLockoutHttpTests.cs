using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Somebody holding the password who keeps guessing codes waits longer every time.</summary>
public class EscalatingLockoutHttpTests
{
    [Test]
    public async Task A_second_lock_from_wrong_codes_lasts_twice_as_long_as_the_first()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        app.Time.Advance(TimeSpan.FromMinutes(15));

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_completed_sign_in_starts_the_next_lock_from_the_first_length_again()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));

        await account.SignInWithSecondFactorAsync();

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_lock_never_grows_past_its_cap()
    {
        await using var app = await TestApp.StartAsync(configure: settings => settings["LocalLogin:LockoutMaxDuration"] = "00:20:00");
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(21));

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_repeated_lock_tells_the_audit_sink_how_many_there_have_been()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        await LockWithWrongCodesAsync(app, account);
        app.Time.Advance(TimeSpan.FromMinutes(16));
        await LockWithWrongCodesAsync(app, account);

        var strikes = recorded.OfType<AccountLockedOut>().Select(locked => locked.Strikes).ToList();

        await Assert.That(strikes).IsEquivalentTo(new[] { 1, 2 });
    }

    /// <summary>The right password and five wrong codes against one challenge, which a mistyped code
    /// does not spend.</summary>
    private static async Task LockWithWrongCodesAsync(TestApp app, Account account)
    {
        var challenge = (await (await account.LoginAsync()).Json()).String("challenge")
            ?? throw new InvalidOperationException("Expected a second-factor challenge.");

        for (var i = 0; i < 5; i++)
        {
            app.Time.AdvanceToNextTotpStep();
            await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.WrongCode(account.Secret!, app.Time.Now) });
        }
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
