using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Who counts as one caller for the rate limiter. Everything the limiter protects rests on that.
/// </summary>
public class RateLimitPartitionHttpTests
{
    /// <summary>
    /// An IPv6 customer is handed a /64. Keyed on the full address, each of those 2^64 addresses
    /// was a budget of its own, so the limiter stopped nobody who had one.
    /// </summary>
    [Test]
    public async Task Addresses_in_one_ipv6_64_share_a_budget()
    {
        await using var app = await StartLimitedAsync(permitLimit: 2);

        var statuses = new List<HttpStatusCode>();

        foreach (var address in new[] { "2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2:ffff::c" })
            statuses.Add((await LoginFromAsync(app, address)).StatusCode);

        await Assert.That(statuses[2]).IsEqualTo(HttpStatusCode.TooManyRequests);
    }

    [Test]
    public async Task Separate_ipv4_addresses_keep_separate_budgets()
    {
        await using var app = await StartLimitedAsync(permitLimit: 1);

        var first = await LoginFromAsync(app, "203.0.113.1");
        var second = await LoginFromAsync(app, "203.0.113.2");

        await Assert.That(first.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(second.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
    }

    /// <summary>
    /// A NAT64 gateway puts every IPv4 client it translates in one /64, so one of them sending ten
    /// wrong passwords a minute gave every IPv4 user behind it 429. The address inside is the caller.
    /// </summary>
    [Test]
    [Arguments("64:ff9b::cb00:7101", "64:ff9b::cb00:7102")]
    [Arguments("64:ff9b:1:cb00:71:100::", "64:ff9b:1:cb00:71:200::")]
    public async Task Ipv4_clients_behind_nat64_keep_separate_budgets(string first, string second)
    {
        await using var app = await StartLimitedAsync(permitLimit: 1);

        var one = await LoginFromAsync(app, first);
        var other = await LoginFromAsync(app, second);
        var again = await LoginFromAsync(app, first);

        await Assert.That(one.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(other.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);

        // Still one budget per IPv4 client, not none.
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
    }

    /// <summary>
    /// A gateway on a prefix of the network's own, which only configuration can name. The /40 puts
    /// the address across the reserved octet, which is skipped, so this is the embedding worked out
    /// rather than a fixed offset.
    /// </summary>
    [Test]
    [Arguments("2001:db8:64::/96", "2001:db8:64::cb00:7101", "2001:db8:64::cb00:7102")]
    [Arguments("2001:db8:100::/40", "2001:db8:1cb:71:1::", "2001:db8:1cb:71:2::")]
    public async Task Ipv4_clients_behind_a_configured_nat64_prefix_keep_separate_budgets(string prefix, string first, string second)
    {
        await using var app = await StartLimitedAsync(
            permitLimit: 1,
            configure: settings => settings["LocalLogin:RateLimit:Nat64Prefixes:0"] = prefix);

        var one = await LoginFromAsync(app, first);
        var other = await LoginFromAsync(app, second);
        var again = await LoginFromAsync(app, first);

        await Assert.That(one.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(other.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
    }

    /// <summary>A prefix that cannot be read would be skipped, and its clients would share one
    /// budget with nothing saying why. Refused at startup instead.</summary>
    [Test]
    [Arguments("2001:db8:64::/72")]
    [Arguments("192.0.2.0/24")]
    [Arguments("not a prefix")]
    public async Task A_nat64_prefix_that_cannot_be_read_refuses_to_start(string prefix)
    {
        var started = async () => await (await StartLimitedAsync(
            permitLimit: 1,
            configure: settings => settings["LocalLogin:RateLimit:Nat64Prefixes:0"] = prefix)).DisposeAsync();

        var refused = await Assert.That(started).Throws<InvalidOperationException>();

        await Assert.That(refused!.Message).Contains("Nat64Prefixes");
    }

    /// <summary>
    /// Behind a proxy with forwarded headers left unconfigured, every caller is the proxy and shares
    /// one limit - ten junk logins a minute and the whole site answers 429. Nothing at startup can
    /// see that, so the first request that shows it says so.
    /// </summary>
    [Test]
    public async Task An_unprocessed_forwarded_header_from_a_private_address_is_warned_about_once()
    {
        var warnings = new ConcurrentQueue<string>();

        await using var app = await StartLimitedAsync(
            permitLimit: 100,
            services => services.AddSingleton<ILoggerProvider>(new WarningCollector(warnings)));

        await LoginFromAsync(app, "10.0.0.5", forwardedFor: "198.51.100.7");
        await LoginFromAsync(app, "10.0.0.5", forwardedFor: "198.51.100.8");

        await Assert.That(warnings.Count(message => message.Contains("X-Forwarded-For"))).IsEqualTo(1);
    }

    [Test]
    public async Task A_direct_caller_is_not_warned_about()
    {
        var warnings = new ConcurrentQueue<string>();

        await using var app = await StartLimitedAsync(
            permitLimit: 100,
            services => services.AddSingleton<ILoggerProvider>(new WarningCollector(warnings)));

        await LoginFromAsync(app, "10.0.0.5");
        await LoginFromAsync(app, "198.51.100.9", forwardedFor: "198.51.100.7");

        await Assert.That(warnings.Count(message => message.Contains("X-Forwarded-For"))).IsEqualTo(0);
    }

    private static Task<TestApp> StartLimitedAsync(
        int permitLimit,
        Action<IServiceCollection>? configureServices = null,
        Action<Dictionary<string, string?>>? configure = null) =>
        TestApp.StartAsync(
            configure: settings =>
            {
                settings["LocalLogin:RateLimit:Enabled"] = "true";
                settings["LocalLogin:RateLimit:PermitLimit"] = permitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture);
                settings["LocalLogin:RateLimit:Window"] = "01:00:00";
                configure?.Invoke(settings);
            },
            configureServices: configureServices);

    private static Task<HttpResponseMessage> LoginFromAsync(TestApp app, string address, string? forwardedFor = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { identifier = "nobody", password = "whatever" }),
        };

        request.Headers.Add(TestApp.RemoteIpHeader, address);

        if (forwardedFor is not null)
            request.Headers.Add("X-Forwarded-For", forwardedFor);

        return app.Client.SendAsync(request);
    }

    private sealed class WarningCollector(ConcurrentQueue<string> warnings) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Collector(warnings);

        public void Dispose()
        {
        }

        private sealed class Collector(ConcurrentQueue<string> warnings) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel))
                    warnings.Enqueue(formatter(state, exception));
            }
        }
    }
}
