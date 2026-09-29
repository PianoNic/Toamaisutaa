using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The instruments as a real request produces them.
/// </summary>
/// <remarks>
/// A meter published from a service the host never resolves records nothing, and the rejection
/// counter in particular lives in an endpoint filter - which exists only because it was attached to
/// a route. Neither is visible from the service suite.
/// </remarks>
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

    /// <summary>
    /// Proves the wiring, not the counting: the service suite already asserts what a sign-in
    /// records, and would go on passing if nothing in the container ever handed the endpoints a
    /// meter to record it on.
    /// </summary>
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
/// Counts one instrument on one host's meter.
/// </summary>
/// <remarks>
/// Bound to the host's own <see cref="Meter"/> instance rather than to the name, because every
/// <see cref="TestApp"/> in the suite publishes a meter called <c>Toamaisutaa</c> and two of them
/// running at once would otherwise count each other.
/// </remarks>
/// <summary>
/// The sign-in series says what the caller was told, and the caller is told the same thing for an
/// unknown name, a wrong password and a locked account. Tagged apart, whoever could read the scrape
/// endpoint learned which of their guesses named a real account.
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

internal sealed class InstrumentProbe : IDisposable
{
    private readonly MeterListener _listener = new();
    private long _total;

    internal InstrumentProbe(TestApp app, string instrumentName)
    {
        var meter = app.Services.GetRequiredService<ToamaisutaaMetrics>().Meter;

        _listener.InstrumentPublished = (instrument, listener) =>
        {
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

    /// <summary>The <c>result</c> tag of every measurement, in order.</summary>
    internal System.Collections.Concurrent.ConcurrentQueue<string?> Results { get; } = new();

    public void Dispose() => _listener.Dispose();
}
