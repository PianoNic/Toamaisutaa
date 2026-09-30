using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

public class MetricsHttpTests
{
    [Test]
    public async Task A_request_the_limiter_refuses_is_counted()
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
        {
            settings["LocalLogin:RateLimit:Enabled"] = "true";
            settings["LocalLogin:RateLimit:PermitLimit"] = "2";
            settings["LocalLogin:RateLimit:Window"] = "00:05:00";
        });

        using var probe = new InstrumentProbe(app, "toamaisutaa.rate_limit.rejections");

        var statuses = new List<HttpStatusCode>();

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var response = await app.Client.PostJson("/auth/login", new { identifier = "nobody", password = "whatever" });
            statuses.Add(response.StatusCode);
        }

        await Assert.That(statuses.Count(status => status == HttpStatusCode.TooManyRequests)).IsEqualTo(2);
        await Assert.That(probe.Total).IsEqualTo(2);
    }

    [Test]
    public async Task A_sign_in_over_HTTP_reaches_the_meter()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        using var probe = new InstrumentProbe(app, "toamaisutaa.sign_in.attempts");

        await account.LoginAsync();

        await Assert.That(probe.Total).IsEqualTo(1);
    }
}

/// <summary>
/// Distinct result tags would let anyone reading the scrape endpoint tell which guesses named a real account.
/// </summary>
public class SignInMetricTagHttpTests
{
    [Test]
    public async Task An_unknown_name_and_a_wrong_password_are_counted_under_one_result()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        using var probe = new InstrumentProbe(app, "toamaisutaa.sign_in.attempts");

        await app.Client.PostJson("/auth/login", new { identifier = "nobody-at-all", password = "whatever" });
        await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });

        var results = probe.Results.ToList();

        await Assert.That(results).HasCount().EqualTo(2);
        await Assert.That(results[0]).IsEqualTo(results[1]);
    }
}

public class LockoutMetricHttpTests
{
    /// <summary>Wrong current passwords lock the account like wrong sign-ins do, and the lockout
    /// counter missed it, so an attack through a stolen token never showed on it.</summary>
    [Test]
    public async Task A_lockout_from_wrong_current_passwords_is_counted()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        using var probe = new InstrumentProbe(app, "toamaisutaa.lockouts");

        for (var i = 0; i < 5; i++)
            await app.Client.PostJson("/auth/password", new { currentPassword = "not the password", newPassword = "a different passphrase" }, account.AccessToken);

        // Locked: the right password is refused too.
        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(probe.Total).IsEqualTo(1);
    }
}

internal sealed class InstrumentProbe : IDisposable
{
    private readonly MeterListener _listener = new();
    private long _total;

    internal InstrumentProbe(TestApp app, string instrumentName)
    {
        var meter = app.Services.GetRequiredService<ToamaisutaaMetrics>().Meter;

        _listener.InstrumentPublished = (instrument, listener) =>
        {
            // Matched by instance, not name, because every TestApp publishes a meter named Toamaisutaa and parallel hosts would count each other.
            if (ReferenceEquals(instrument.Meter, meter) && instrument.Name == instrumentName)
                listener.EnableMeasurementEvents(instrument);
        };

        _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            Interlocked.Add(ref _total, value);

            foreach (var tag in tags)
            {
                if (tag.Key == "result")
                    Results.Enqueue(tag.Value?.ToString());
            }
        });

        // Histograms record a double per event; each one is an occurrence, whatever it measured.
        _listener.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            Interlocked.Increment(ref _total);

            foreach (var tag in tags)
            {
                if (tag.Key == "result")
                    Results.Enqueue(tag.Value?.ToString());
            }
        });

        _listener.Start();
    }

    internal long Total => Interlocked.Read(ref _total);

    internal System.Collections.Concurrent.ConcurrentQueue<string?> Results { get; } = new();

    public void Dispose() => _listener.Dispose();
}
