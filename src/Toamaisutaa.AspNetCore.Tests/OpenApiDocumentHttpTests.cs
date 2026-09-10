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

/// <summary>
/// The security half of the generated document, read as the JSON an API explorer reads.
/// </summary>
/// <remarks>
/// These used to be thirty-five lines pasted into every application, and a pasted transformer
/// drifts - one deployment hardcoded Keycloak's authorization URL while running Pocket ID. Now that
/// the package owns them, the document is a response shape like any other: asserted off raw JSON,
/// never through the types that produced it.
/// </remarks>
public class OpenApiDocumentHttpTests
{
    private const string Authority = "http://localhost/issuer";

    private const string DiscoveryPath = "/issuer/.well-known/openid-configuration";

    /// <summary>
    /// The issuer, served by the application under test. Its endpoints are deliberately on another
    /// host, the way a real discovery document's are, so an assertion on them cannot pass by
    /// accidentally matching this host.
    /// </summary>
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

        // No Oidc:Authority here, which is a deployment that only issues its own tokens. There is no
        // authorization server to describe, and nothing invents one.
        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });
    }

    [Test]
    public async Task An_anonymous_endpoint_carries_an_empty_requirement_and_a_protected_one_carries_none()
    {
        await using var app = await TestApp.StartAsync(includeOpenApi: true);

        var paths = (await Document(app)).GetProperty("paths");

        // Empty, not absent: an absent list inherits the document's requirement, which would put a
        // padlock on the endpoint you call because you have no token yet.
        var login = paths.GetProperty("/auth/login").GetProperty("post");
        await Assert.That(login.TryGetProperty("security", out var security)).IsTrue();
        await Assert.That(security.GetArrayLength()).IsEqualTo(0);

        // Absent, so the document's requirement stands.
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

        // Two requirements rather than one holding both schemes: either token opens the padlock, and
        // one object would mean a caller has to present both.
        await Assert.That(document.GetProperty("security").GetArrayLength()).IsEqualTo(2);
        await Assert.That(RequiredSchemes(document)).IsEquivalentTo(new[] { "Bearer", "OAuth2" });
    }

    [Test]
    public async Task An_issuer_that_does_not_answer_leaves_the_rest_of_the_document_alone()
    {
        // Configured, and nothing serving it - the shape of an identity provider that is down while
        // somebody is reading the API documentation.
        await using var app = await TestApp.StartAsync(configure: WithIssuer, includeOpenApi: true);

        var document = await Document(app);

        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });
        await Assert.That(RequiredSchemes(document)).IsEquivalentTo(new[] { "Bearer" });
    }

    [Test]
    public async Task Issuer_metadata_over_plaintext_is_refused_unless_the_deployment_says_otherwise()
    {
        // A host with no bearer registration at all, which is both a supported way to use this
        // package and the only way to reach this branch: with the bearer handler present, a
        // plaintext authority and Oidc:RequireHttpsMetadata on throws on the first request, so no
        // document could be fetched to assert against.
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

        // The metadata route answers, and Oidc:RequireHttpsMetadata defaults to on, so the fetch
        // never happens - the same rule the bearer handler applies to its own discovery.
        var document = await (await app.GetTestClient().Get("/openapi/v1.json")).Json();

        await Assert.That(Schemes(document).Names()).IsEquivalentTo(new[] { "Bearer" });

        await app.StopAsync();
    }
}
