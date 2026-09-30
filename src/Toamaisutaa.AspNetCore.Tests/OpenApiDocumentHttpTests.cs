using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class OpenApiDocumentHttpTests
{
    private const string Authority = "http://localhost/issuer";

    private const string DiscoveryPath = "/issuer/.well-known/openid-configuration";

    private const string PublicAuthority = "https://id.example.test/issuer";

    private const string InternalAuthority = "http://localhost/internal";

    /// <summary>Endpoints are on another host so an assertion on them cannot pass by accidentally matching this one.</summary>
    private static void MapIssuerMetadata(IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet(DiscoveryPath, () => Results.Json(new Dictionary<string, string>
        {
            ["issuer"] = Authority,
            ["authorization_endpoint"] = "https://id.example.test/authorize",
            ["token_endpoint"] = "https://id.example.test/token",
        }))
        .AllowAnonymous();

    private static void WithIssuer(Dictionary<string, string?> settings)
    {
        settings["Oidc:Authority"] = Authority;
        settings["Oidc:RequireHttpsMetadata"] = "false";
        settings["Oidc:Scope"] = "openid profile roles";
    }

    private static Action<Dictionary<string, string?>> ThroughAnInternalAuthority(string internalAuthority) =>
        settings =>
        {
            settings["Oidc:Authority"] = PublicAuthority;
            settings["Oidc:InternalAuthority"] = internalAuthority;
            settings["Oidc:RequireHttpsMetadata"] = "false";
            settings["Oidc:Scope"] = "openid profile";
        };

    private static Action<IEndpointRouteBuilder> MapInternalIssuerMetadata(
        string internalAuthority,
        string authorization,
        string token) =>
        endpoints => endpoints.MapGet(
            $"{new Uri(internalAuthority).AbsolutePath.TrimEnd('/')}/.well-known/openid-configuration",
            () => Results.Json(new Dictionary<string, string>
            {
                ["issuer"] = PublicAuthority,
                ["authorization_endpoint"] = authorization,
                ["token_endpoint"] = token,
            }))
        .AllowAnonymous();

    private static JsonElement AuthorizationCodeFlow(JsonElement document) =>
        Schemes(document).GetProperty("OAuth2").GetProperty("flows").GetProperty("authorizationCode");

    private static async Task<JsonElement> Document(TestApp app)
    {
        var response = await app.Client.Get("/openapi/v1.json");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        return await response.Json();
    }

    private static JsonElement Schemes(JsonElement document) =>
        document.GetProperty("components").GetProperty("securitySchemes");

    private static IReadOnlyList<string> RequiredSchemes(JsonElement document) =>
        [.. document.GetProperty("security").EnumerateArray().SelectMany(requirement => requirement.Names())];

    [Test]
    public async Task The_document_declares_a_bearer_scheme_and_requires_it_everywhere()
    {
        await using var app = await TestApp.StartAsync(includeOpenApi: true);

        var document = await Document(app);
        var bearer = Schemes(document).GetProperty("Bearer");

        await Assert.That(bearer.String("type")).IsEqualTo("http");
        await Assert.That(bearer.String("scheme")).IsEqualTo("bearer");
        await Assert.That(bearer.String("bearerFormat")).IsEqualTo("JWT");
        await Assert.That(RequiredSchemes(document)).IsEquivalentTo(new[] { "Bearer" });

        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });
    }

    [Test]
    public async Task The_document_declares_the_statuses_and_bodies_these_endpoints_give()
    {
        await using var app = await TestApp.StartAsync(includeOpenApi: true);

        var paths = (await Document(app)).GetProperty("paths");

        var revoke = paths.GetProperty("/auth/invitations/revoke").GetProperty("post").GetProperty("responses");
        await Assert.That(revoke.TryGetProperty("400", out _)).IsTrue();

        var cooledDown = paths.GetProperty("/auth/email").GetProperty("post").GetProperty("responses").GetProperty("429");
        await Assert.That(cooledDown.TryGetProperty("content", out _)).IsTrue();
    }

    [Test]
    public async Task An_anonymous_endpoint_carries_an_empty_requirement_and_a_protected_one_carries_none()
    {
        await using var app = await TestApp.StartAsync(includeOpenApi: true);

        var paths = (await Document(app)).GetProperty("paths");

        // Empty, not absent, because an absent list inherits the document's requirement.
        var login = paths.GetProperty("/auth/login").GetProperty("post");
        await Assert.That(login.TryGetProperty("security", out var security)).IsTrue();
        await Assert.That(security.GetArrayLength()).IsEqualTo(0);

        var me = paths.GetProperty("/test/me").GetProperty("get");
        await Assert.That(me.TryGetProperty("security", out _)).IsFalse();
    }

    [Test]
    public async Task The_oauth2_scheme_takes_its_urls_from_the_issuer_discovery_document()
    {
        await using var app = await TestApp.StartAsync(MapIssuerMetadata, WithIssuer, includeOpenApi: true);

        var document = await Document(app);
        var flow = Schemes(document).GetProperty("OAuth2").GetProperty("flows").GetProperty("authorizationCode");

        await Assert.That(flow.String("authorizationUrl")).IsEqualTo("https://id.example.test/authorize");
        await Assert.That(flow.String("tokenUrl")).IsEqualTo("https://id.example.test/token");
        await Assert.That(flow.GetProperty("scopes").Names()).IsEquivalentTo(new[] { "openid", "profile", "roles" });

        // Two requirements, because one object holding both schemes would demand both tokens.
        await Assert.That(document.GetProperty("security").GetArrayLength()).IsEqualTo(2);
        await Assert.That(RequiredSchemes(document)).IsEquivalentTo(new[] { "Bearer", "OAuth2" });
    }

    [Test]
    public async Task An_issuer_that_does_not_answer_leaves_the_rest_of_the_document_alone()
    {
        await using var app = await TestApp.StartAsync(configure: WithIssuer, includeOpenApi: true);

        var document = await Document(app);

        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });
        await Assert.That(RequiredSchemes(document)).IsEquivalentTo(new[] { "Bearer" });
    }

    [Test]
    public async Task Issuer_metadata_over_plaintext_is_refused_unless_the_deployment_says_otherwise()
    {
        // No bearer registration, because with it a plaintext authority throws on the first request and no document could be fetched.
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Critical);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = Authority,
        });

        builder.Services.AddToamaisutaaOpenApi(builder.Configuration);
        builder.Services
            .AddHttpClient(ToamaisutaaDefaults.DiscoveryHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(services => ((TestServer)services.GetRequiredService<IServer>()).CreateHandler());

        await using var app = builder.Build();

        app.MapOpenApi();
        MapIssuerMetadata(app);

        await app.StartAsync();

        // The metadata route answers, so only the RequireHttpsMetadata default stops the fetch.
        var document = await (await app.GetTestClient().Get("/openapi/v1.json")).Json();

        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });

        await app.StopAsync();
    }

    [Test]
    public async Task An_endpoint_answered_at_the_internal_address_is_moved_onto_the_public_authority()
    {
        // Keycloak without KC_HOSTNAME builds endpoint URLs from the Host header of the internal hop.
        await using var app = await TestApp.StartAsync(
            MapInternalIssuerMetadata(
                InternalAuthority,
                $"{InternalAuthority}/protocol/openid-connect/auth",
                $"{InternalAuthority}/protocol/openid-connect/token"),
            ThroughAnInternalAuthority(InternalAuthority),
            includeOpenApi: true);

        var flow = AuthorizationCodeFlow(await Document(app));

        await Assert.That(flow.String("authorizationUrl"))
            .IsEqualTo($"{PublicAuthority}/protocol/openid-connect/auth");
        await Assert.That(flow.String("tokenUrl")).IsEqualTo($"{PublicAuthority}/protocol/openid-connect/token");
        await Assert.That(flow.String("refreshUrl")).IsEqualTo($"{PublicAuthority}/protocol/openid-connect/token");
    }

    /// <summary>
    /// One case per guard: another host, and the same host outside the internal authority's path.
    /// </summary>
    [Test]
    [Arguments("http://localhost", "https://login.example.test/authorize", "https://login.example.test/token")]
    [Arguments(InternalAuthority, "http://localhost/other/authorize", "http://localhost/other/token")]
    public async Task An_endpoint_that_is_not_the_internal_authoritys_is_left_exactly_as_the_issuer_gave_it(
        string internalAuthority,
        string authorization,
        string token)
    {
        await using var app = await TestApp.StartAsync(
            MapInternalIssuerMetadata(internalAuthority, authorization, token),
            ThroughAnInternalAuthority(internalAuthority),
            includeOpenApi: true);

        var flow = AuthorizationCodeFlow(await Document(app));

        await Assert.That(flow.String("authorizationUrl")).IsEqualTo(authorization);
        await Assert.That(flow.String("tokenUrl")).IsEqualTo(token);
    }

    [Test]
    public async Task The_issuer_is_asked_once_however_many_readers_the_document_has()
    {
        var fetches = 0;

        await using var app = await TestApp.StartAsync(
            endpoints => endpoints.MapGet(DiscoveryPath, () =>
            {
                Interlocked.Increment(ref fetches);

                return Results.Json(new Dictionary<string, string>
                {
                    ["issuer"] = Authority,
                    ["authorization_endpoint"] = "https://id.example.test/authorize",
                    ["token_endpoint"] = "https://id.example.test/token",
                });
            })
            .AllowAnonymous(),
            WithIssuer,
            includeOpenApi: true);

        await Document(app);
        await Document(app);
        await Document(app);

        await Assert.That(fetches).IsEqualTo(1);

        app.Time.Advance(TimeSpan.FromMinutes(6));

        var flow = AuthorizationCodeFlow(await Document(app));

        await Assert.That(fetches).IsEqualTo(2);
        await Assert.That(flow.String("authorizationUrl")).IsEqualTo("https://id.example.test/authorize");
    }
}
