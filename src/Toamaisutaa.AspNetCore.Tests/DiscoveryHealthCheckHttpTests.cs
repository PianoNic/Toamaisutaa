using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Over HTTP rather than against the check object, because the promise is the status code an
/// orchestrator acts on, which a test reading <c>HealthCheckResult.Status</c> would not see.</summary>
public class DiscoveryHealthCheckHttpTests
{
    private const string Issuer = "https://id.example.test";

    // Written out rather than read from ToamaisutaaDefaults: consumers configure against these names,
    // and an assertion that reads them from the package agrees with a rename.
    private const string CheckName = "toamaisutaa-oidc-discovery";
    private const string HttpClientName = "toamaisutaa-discovery";
    private const string ReadyTag = "ready";

    private sealed class FakeIssuer : HttpMessageHandler
    {
        private int _requests;

        public int Requests => Volatile.Read(ref _requests);

        public string? LastAddress { get; private set; }

        public Func<HttpResponseMessage> Respond { get; set; } = () => Document(Issuer);

        /// <summary>Yields while waiting, so requests that arrive together really are in flight together.</summary>
        public TimeSpan Latency { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            LastAddress = request.RequestUri?.ToString();

            if (Latency > TimeSpan.Zero)
                await Task.Delay(Latency, cancellationToken);

            return Respond();
        }

        public static HttpResponseMessage Document(string issuer) => Body(
            HttpStatusCode.OK,
            $$"""{"issuer":"{{issuer}}","jwks_uri":"{{issuer}}/jwks","authorization_endpoint":"{{issuer}}/auth"}""");

        public static HttpResponseMessage Body(HttpStatusCode status, string body) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }

    private static async Task<TestApp> StartAsync(FakeIssuer issuer, Action<Dictionary<string, string?>>? configure = null)
    {
        return await TestApp.StartAsync(
            mapExtra: endpoints =>
            {
                // Anonymous on purpose: the fallback policy this package registers would otherwise
                // answer 401, and an orchestrator reads that as a failing probe.
                endpoints.MapHealthChecks("/health").AllowAnonymous();
                endpoints.MapHealthChecks("/health/detail", new HealthCheckOptions { ResponseWriter = WriteEntries }).AllowAnonymous();

                // The endpoint docs/oidc.md hands consumers, copied rather than referenced.
                endpoints.MapHealthChecks(
                    "/ready",
                    new HealthCheckOptions { Predicate = check => check.Tags.Contains(ReadyTag) }).AllowAnonymous();
            },
            configure: settings =>
            {
                settings["Oidc:Authority"] = Issuer;
                settings["Oidc:HealthCheck:RefreshInterval"] = "00:01:00";
                configure?.Invoke(settings);
            },
            configureServices: services =>
            {
                services.AddToamaisutaaHealthChecks();
                services.AddHttpClient(HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => issuer);
            });
    }

    private static Task WriteEntries(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";

        var entries = report.Entries.ToDictionary(
            entry => entry.Key,
            entry => new Dictionary<string, string?>
            {
                ["status"] = entry.Value.Status.ToString(),
                ["description"] = entry.Value.Description,
            });

        return context.Response.WriteAsync(JsonSerializer.Serialize(entries));
    }

    [Test]
    public async Task A_reachable_discovery_document_answers_200_and_Healthy()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(issuer);

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Healthy");
        await Assert.That(issuer.LastAddress).IsEqualTo($"{Issuer}/.well-known/openid-configuration");
    }

    [Test]
    public async Task The_check_is_reported_under_its_own_name_and_names_the_address_it_probed()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(issuer);

        var entry = (await (await app.Client.Get("/health/detail")).Json()).GetProperty(CheckName);

        await Assert.That(entry.String("status")).IsEqualTo("Healthy");
        await Assert.That(entry.String("description")).Contains($"{Issuer}/.well-known/openid-configuration");
    }

    [Test]
    public async Task An_internal_authority_is_what_gets_probed()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(
            issuer,
            settings => settings["Oidc:InternalAuthority"] = "https://keycloak.internal/realms/main/");

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(issuer.LastAddress).IsEqualTo("https://keycloak.internal/realms/main/.well-known/openid-configuration");
    }

    [Test]
    public async Task An_unreachable_issuer_answers_503_and_Unhealthy()
    {
        var issuer = new FakeIssuer { Respond = () => throw new HttpRequestException("Connection refused") };
        await using var app = await StartAsync(issuer);

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Unhealthy");
    }

    [Test]
    public async Task A_200_that_is_not_a_discovery_document_answers_503_and_Unhealthy()
    {
        var issuer = new FakeIssuer { Respond = () => FakeIssuer.Body(HttpStatusCode.OK, """{"error":"not found"}""") };
        await using var app = await StartAsync(issuer);

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Unhealthy");
    }

    [Test]
    public async Task A_document_that_was_fetched_inside_the_refresh_interval_is_answered_without_asking_the_issuer_again()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(issuer);

        await app.Client.Get("/health");
        issuer.Respond = () => throw new HttpRequestException("Connection refused");

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Healthy");
        await Assert.That(issuer.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task A_failing_issuer_is_asked_once_per_refresh_interval_not_once_per_probe()
    {
        var issuer = new FakeIssuer { Respond = () => throw new HttpRequestException("Connection refused") };
        await using var app = await StartAsync(issuer);

        for (var i = 0; i < 5; i++)
            await Assert.That((await app.Client.Get("/health")).StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);

        await Assert.That(issuer.Requests).IsEqualTo(1);

        app.Time.Advance(TimeSpan.FromSeconds(61));
        await app.Client.Get("/health");

        await Assert.That(issuer.Requests).IsEqualTo(2);
    }

    [Test]
    public async Task Probes_arriving_together_send_one_request()
    {
        var issuer = new FakeIssuer { Latency = TimeSpan.FromMilliseconds(500) };

        await using var app = await StartAsync(issuer);

        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => app.Client.Get("/health")));

        await Assert.That(issuer.Requests).IsEqualTo(1);
    }

    /// <summary>The caller cancels before the issuer answers, and the fetch must still complete and be
    /// cached rather than die with the probe that started it.</summary>
    [Test]
    public async Task A_probe_its_caller_gave_up_on_still_answers_the_next_one()
    {
        var issuer = new FakeIssuer { Latency = TimeSpan.FromMilliseconds(500) };

        await using var app = await StartAsync(issuer);
        var health = app.Services.GetRequiredService<HealthCheckService>();

        using (var impatient = new CancellationTokenSource(TimeSpan.FromMilliseconds(50)))
        {
            await Assert.That(async () => await health.CheckHealthAsync(impatient.Token)).Throws<OperationCanceledException>();
        }

        await Task.Delay(TimeSpan.FromSeconds(1));

        var report = await health.CheckHealthAsync();

        await Assert.That(report.Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(issuer.Requests).IsEqualTo(1);
    }

    /// <summary>Degraded rather than unhealthy, because the handler still validates tokens against the
    /// document it holds.</summary>
    [Test]
    public async Task A_cached_document_served_past_its_refresh_interval_answers_200_and_Degraded()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(issuer);

        await app.Client.Get("/health");
        issuer.Respond = () => throw new HttpRequestException("Connection refused");
        app.Time.Advance(TimeSpan.FromSeconds(90));

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Degraded");
        await Assert.That(issuer.Requests).IsEqualTo(2);
    }

    /// <summary>Degraded is a 200 that keeps the instance in the load balancer, so one old success must
    /// not keep it there forever.</summary>
    [Test]
    public async Task A_cached_document_older_than_the_degraded_window_answers_503_and_Unhealthy()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(
            issuer,
            settings => settings["Oidc:HealthCheck:DegradedFor"] = "00:05:00");

        await app.Client.Get("/health");
        issuer.Respond = () => throw new HttpRequestException("Connection refused");
        app.Time.Advance(TimeSpan.FromMinutes(6));

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Unhealthy");
    }

    [Test]
    public async Task Dropping_out_of_the_degraded_window_names_the_setting_that_decided_it()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(
            issuer,
            settings => settings["Oidc:HealthCheck:DegradedFor"] = "00:05:00");

        await app.Client.Get("/health");
        issuer.Respond = () => throw new HttpRequestException("Connection refused");
        app.Time.Advance(TimeSpan.FromMinutes(6));

        var entry = (await (await app.Client.Get("/health/detail")).Json()).GetProperty(CheckName);

        await Assert.That(entry.String("status")).IsEqualTo("Unhealthy");
        await Assert.That(entry.String("description")).Contains("Oidc:HealthCheck:DegradedFor");
    }

    /// <summary>An empty selection answers 200, so against an unreachable issuer a 200 can only mean the
    /// tag matched no registration.</summary>
    [Test]
    public async Task A_readiness_endpoint_selecting_the_ready_tag_answers_503_and_Unhealthy()
    {
        var issuer = new FakeIssuer { Respond = () => throw new HttpRequestException("Connection refused") };
        await using var app = await StartAsync(issuer);

        var response = await app.Client.Get("/ready");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Unhealthy");
    }

    [Test]
    public async Task No_issuer_configured_answers_503_and_Unhealthy()
    {
        var issuer = new FakeIssuer();
        await using var app = await StartAsync(issuer, settings => settings["Oidc:Authority"] = null);

        var response = await app.Client.Get("/health");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("Unhealthy");
        await Assert.That(issuer.Requests).IsEqualTo(0);
    }
}
