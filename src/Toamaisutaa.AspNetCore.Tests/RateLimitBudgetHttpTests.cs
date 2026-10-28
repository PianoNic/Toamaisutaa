using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Who spends which budget: a signed-in caller its own, a shared network the network's.</summary>
public class RateLimitBudgetHttpTests
{
    private const string School = "203.0.113.7";

    [Test]
    public async Task A_signed_in_caller_reads_sessions_after_strangers_on_its_address_spent_the_budget()
    {
        await using var app = await StartLimitedAsync(permitLimit: 3);
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 3; i++)
            await SendAsync(app, HttpMethod.Post, "/auth/login", School, body: new { identifier = "nobody", password = "whatever" });

        var junk = await SendAsync(app, HttpMethod.Post, "/auth/login", School, body: new { identifier = "nobody", password = "whatever" });
        var sessions = await SendAsync(app, HttpMethod.Get, "/auth/sessions", School, accessToken: account.AccessToken);

        await Assert.That(junk.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(sessions.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Signed_in_reads_do_not_spend_the_budget_of_the_address_they_come_from()
    {
        await using var app = await StartLimitedAsync(permitLimit: 3);
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await SendAsync(app, HttpMethod.Get, "/auth/sessions", School, accessToken: account.AccessToken);

        var login = await SendAsync(app, HttpMethod.Post, "/auth/login", School, body: new { identifier = "nobody", password = "whatever" });

        await Assert.That(login.StatusCode).IsNotEqualTo(HttpStatusCode.TooManyRequests);
    }

    /// <summary>Otherwise registering a throwaway account would buy a fresh budget for password guessing.</summary>
    [Test]
    public async Task A_token_sent_to_an_anonymous_endpoint_buys_no_budget_of_its_own()
    {
        await using var app = await StartLimitedAsync(permitLimit: 2);
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 2; i++)
            await SendAsync(app, HttpMethod.Post, "/auth/login", School, body: new { identifier = "nobody", password = "whatever" });

        var withToken = await SendAsync(
            app, HttpMethod.Post, "/auth/login", School, body: new { identifier = "nobody", password = "whatever" }, accessToken: account.AccessToken);

        await Assert.That(withToken.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
    }

    [Test]
    public async Task A_shared_network_spends_its_own_larger_budget()
    {
        await using var app = await StartLimitedAsync(
            permitLimit: 2,
            configure: settings =>
            {
                settings["LocalLogin:RateLimit:SharedNetworks:0"] = "203.0.113.0/24";
                settings["LocalLogin:RateLimit:SharedNetworkPermitLimit"] = "6";
            });

        var shared = new List<HttpStatusCode>();

        for (var i = 0; i < 7; i++)
            shared.Add((await SendAsync(app, HttpMethod.Post, "/auth/login", $"203.0.113.{10 + (i % 2)}", body: new { identifier = "nobody", password = "whatever" })).StatusCode);

        var elsewhere = new List<HttpStatusCode>();

        for (var i = 0; i < 3; i++)
            elsewhere.Add((await SendAsync(app, HttpMethod.Post, "/auth/login", "198.51.100.1", body: new { identifier = "nobody", password = "whatever" })).StatusCode);

        await Assert.That(shared.Take(6)).DoesNotContain(HttpStatusCode.TooManyRequests);
        await Assert.That(shared[6]).IsEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(elsewhere[2]).IsEqualTo(HttpStatusCode.TooManyRequests);
    }

    [Test]
    public async Task Startup_refuses_a_shared_network_that_is_not_one()
    {
        var started = async () =>
        {
            await using var app = await StartLimitedAsync(
                permitLimit: 2,
                configure: settings => settings["LocalLogin:RateLimit:SharedNetworks:0"] = "the school");
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("the school");
    }

    private static Task<TestApp> StartLimitedAsync(int permitLimit, Action<Dictionary<string, string?>>? configure = null) =>
        TestApp.StartAsync(configure: settings =>
        {
            settings["LocalLogin:RateLimit:Enabled"] = "true";
            settings["LocalLogin:RateLimit:PermitLimit"] = permitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture);
            settings["LocalLogin:RateLimit:Window"] = "01:00:00";
            configure?.Invoke(settings);
        });

    private static Task<HttpResponseMessage> SendAsync(
        TestApp app,
        HttpMethod method,
        string path,
        string remoteIp,
        object? body = null,
        string? accessToken = null)
    {
        var request = new HttpRequestMessage(method, path);

        if (body is not null)
            request.Content = JsonContent.Create(body);

        if (accessToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        request.Headers.Add(TestApp.RemoteIpHeader, remoteIp);
        return app.Client.SendAsync(request);
    }
}
