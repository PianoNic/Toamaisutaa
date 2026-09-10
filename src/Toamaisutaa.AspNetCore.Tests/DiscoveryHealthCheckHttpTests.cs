using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// What a readiness probe reads when the issuer is fine, when it is gone, and when it went away
/// after having been fine once.
/// </summary>
/// <remarks>
/// Over HTTP rather than against the check object, because the thing being promised is a status
/// code an orchestrator acts on: 200 keeps a pod in the load balancer and 503 takes it out. A test
/// that only read <c>HealthCheckResult.Status</c> would agree with the check while the endpoint in
/// front of it answered something else.
/// </remarks>
public class DiscoveryHealthCheckHttpTests
{
    private const string Issuer = "https://id.example.test";

    // Written out rather than read from ToamaisutaaDefaults: all three are names a consumer
    // configures against - one selects the entry in a health report, one is where a handler is
    // attached to the probe, one is what a readiness endpoint filters on - and an assertion that
    // reads them from the package agrees with a rename.
    private const string CheckName = "toamaisutaa-oidc-discovery";
    private const string HttpClientName = "toamaisutaa-discovery";
    private const string ReadyTag = "ready";

    /// <summary>
    /// Stands in for the issuer. A stub handler rather than a second host: the failures worth
    /// testing here are a refused connection and a 200 that is not a discovery document, and both
    /// are easier to produce than to arrange.
    /// </summary>
    private sealed class FakeIssuer : HttpMessageHandler
    {
        public int Requests { get; private set; }

        public string? LastAddress { get; private set; }

        public Func<HttpResponseMessage> Respond { get; set; } = () => Document(Issuer);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            LastAddress = request.RequestUri?.ToString();

            return Task.FromResult(Respond());
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

    /// <summary>
    /// The detail a status code cannot carry, keyed by the name each check is registered under.
    /// Stands in for whatever an application writes when it wants more than Healthy or Unhealthy.
    /// </summary>
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

    /// <summary>Discovery moves to the internal address; the issuer in the tokens does not.</summary>
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

    /// <summary>
    /// A reverse proxy that has lost its route answers 200 with a sign-in page. The handler needs
    /// the keys, so a 200 that carries none is a failure however healthy it looks.
    /// </summary>
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

    /// <summary>
    /// Degraded rather than unhealthy: the handler is still validating tokens against the document
    /// it holds, and taking the pod out of rotation for that would be the wrong call.
    /// </summary>
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

    /// <summary>
    /// The other end of the same distinction. Degraded is a 200 and a 200 keeps the instance in the
    /// load balancer, so a fetch that succeeded once must not keep it there for the life of the
    /// process while every request carrying a token 401s.
    /// </summary>
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

    /// <summary>The knob is named in the message, because it is the one thing an operator reading
    /// this can act on without going and finding the source.</summary>
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

    /// <summary>
    /// The readiness endpoint the docs hand out, and the reason it is worth a test of its own: an
    /// empty selection aggregates to Healthy and answers 200, so a renamed or dropped tag produces a
    /// probe that is green because it is checking nothing. Against an unreachable issuer a 200 can
    /// only mean the predicate matched no registration.
    /// </summary>
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
