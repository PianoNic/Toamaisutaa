using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.PasswordValidation.Hibp;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// <c>Toamaisutaa.PasswordValidation.Hibp</c> behind the real pipeline, with a stub in place of the
/// range API.
/// </summary>
/// <remarks>
/// The unit tests say the validator decides correctly. These say the decision reaches the wire: a
/// breached password comes back 400 with the message in <c>errors</c>, and the range API being
/// unreachable comes back 201 rather than 500. The second is the one worth having - failing open is
/// a claim about behaviour under a failure nobody will reproduce by hand.
/// </remarks>
public class HibpPasswordValidationHttpTests
{
    private const string Breached = "correct horse battery staple";

    // SHA-1 of the password above, computed outside this solution:
    // ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42. The stub answers as the range API would.
    private const string BreachedSuffix = "AD6438836DBE526AA231ABDE2D0EEF74D42";

    private static Task<TestApp> StartAsync(Func<HttpRequestMessage, Task<HttpResponseMessage>> range) =>
        TestApp.StartAsync(configureServices: services =>
        {
            services.AddToamaisutaaHibpPasswordValidation(_ => { });
            services.AddHttpClient(ToamaisutaaHibpDefaults.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => new StubRangeApi(range));
        });

    private static Task<HttpResponseMessage> Breach(HttpRequestMessage _) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{BreachedSuffix}:4213\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1"),
        });

    private static Task<HttpResponseMessage> NothingKnown(HttpRequestMessage _) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("0018A45C4D1DEF81644B54AB7F969B88D65:1"),
        });

    private static Task<HttpResponseMessage> Unreachable(HttpRequestMessage _) =>
        Task.FromException<HttpResponseMessage>(new HttpRequestException("no route to host"));

    private static IReadOnlyList<string> Errors(JsonElement body) =>
        body.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array
            ? [.. errors.EnumerateArray().Select(error => error.GetString()!)]
            : [];

    [Test]
    public async Task Registering_with_a_breached_password_is_refused()
    {
        await using var app = await StartAsync(Breach);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "ada", email = "ada@example.com", password = Breached });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var errors = Errors(await response.Json());
        await Assert.That(errors).HasSingleItem();
        await Assert.That(errors[0]).Contains("data breach");
    }

    [Test]
    public async Task Registering_with_a_password_the_corpus_does_not_know_succeeds()
    {
        await using var app = await StartAsync(NothingKnown);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "ada", email = "ada@example.com", password = Breached });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That((await response.Json()).String("access_token")).IsNotNull();
    }

    // The claim the package makes about a down third party, asserted at the only place it matters.
    [Test]
    public async Task Registering_still_works_when_the_range_api_is_unreachable()
    {
        await using var app = await StartAsync(Unreachable);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "ada", email = "ada@example.com", password = Breached });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That((await response.Json()).String("access_token")).IsNotNull();
    }

    // Composed, not substituted. If the breach check had replaced the length rules this would come
    // back 201.
    [Test]
    public async Task The_length_rule_still_answers_with_the_breach_check_installed()
    {
        await using var app = await StartAsync(NothingKnown);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "ada", email = "ada@example.com", password = "short" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var errors = Errors(await response.Json());
        await Assert.That(errors).HasSingleItem();
        await Assert.That(errors[0]).Contains("at least");
    }

    [Test]
    public async Task Changing_a_password_to_a_breached_one_is_refused()
    {
        await using var app = await StartAsync(Breach);

        // Registration would be refused for the same reason, so the account starts on a password the
        // stub does not report, and only the change is asked about.
        var register = await app.Client.PostJson(
            "/auth/register",
            new { userName = "ada", email = "ada@example.com", password = "a password the stub is silent on" });

        var accessToken = (await register.Json()).String("access_token")!;

        var response = await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = "a password the stub is silent on", newPassword = Breached },
            accessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(Errors(await response.Json())[0]).Contains("data breach");
    }

    /// <summary>The range API, replaced. Nothing in this suite reaches the network.</summary>
    private sealed class StubRangeApi(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(request);
    }
}
