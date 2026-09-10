using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// What <c>ICurrentUser</c> reports about the caller, over a real request carrying a real token.
/// </summary>
/// <remarks>
/// The claims only exist once a token has been minted, validated and turned into a principal, and
/// which claim type the roles land under is decided in three places - the issuer, the bearer
/// handler and here. A test that built the principal by hand would agree with itself, so these
/// sign in first. The exception is the fallback to .NET's own role claim type, which by definition
/// wants a principal that came from somewhere other than this pipeline.
/// </remarks>
public class CurrentUserHttpTests
{
    /// <summary>Stands in for an application's own roles table, which this package does not ship.</summary>
    private sealed class FixedRoleProvider(params string[] roles) : IUserRoleProvider
    {
        public Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>(roles);
    }

    private static void MapCurrentUser(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/test/current-user", (ICurrentUser currentUser) => Results.Ok(new
        {
            roles = currentUser.Roles,
            gatekeeper = currentUser.IsInRole("gatekeeper"),
            cased = currentUser.IsInRole("Gatekeeper"),
            stranger = currentUser.IsInRole("keymaster"),
            userName = currentUser.FindClaim("preferred_username"),
            absent = currentUser.FindClaim("tenant_id"),
        }));

        // A principal this package's bearer pipeline did not build: an application authenticating
        // with cookies, or filling the identity from a table of its own. Roles land under the .NET
        // claim type there, which is the fallback under test.
        endpoints.MapGet("/test/current-user/dotnet-roles", (HttpContext context) =>
        {
            context.User = new ClaimsPrincipal(
                new ClaimsIdentity([new Claim(ClaimTypes.Role, "gatekeeper")], "TestScheme"));

            var currentUser = context.RequestServices.GetRequiredService<ICurrentUser>();

            return Results.Ok(new { roles = currentUser.Roles, gatekeeper = currentUser.IsInRole("gatekeeper") });
        })
        .AllowAnonymous();

        endpoints.MapGet("/test/current-user/open", (ICurrentUser currentUser) => Results.Ok(new
        {
            roles = currentUser.Roles,
            gatekeeper = currentUser.IsInRole("gatekeeper"),
            userName = currentUser.FindClaim("preferred_username"),
        }))
        .AllowAnonymous();
    }

    private static Task<TestApp> StartAsync(string? roleClaim = null, params string[] roles) =>
        TestApp.StartAsync(
            MapCurrentUser,
            configure: settings =>
            {
                if (roleClaim is not null)
                    settings["Oidc:RoleClaim"] = roleClaim;
            },
            configureServices: services => services.AddSingleton<IUserRoleProvider>(new FixedRoleProvider(roles)));

    [Test]
    public async Task Roles_come_off_the_token_and_IsInRole_matches_ordinally()
    {
        await using var app = await StartAsync(roles: ["gatekeeper", "archivist"]);
        var account = await Account.RegisterAsync(app);

        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(body.Strings("roles")).IsEquivalentTo(new[] { "gatekeeper", "archivist" });
        await Assert.That(body.Bool("gatekeeper")).IsTrue();
        await Assert.That(body.Bool("stranger")).IsFalse();

        // Ordinal, which is what RequireRole does. A role check that quietly ignored case would
        // grant on a value the authorization layer refuses.
        await Assert.That(body.Bool("cased")).IsFalse();
    }

    /// <summary>
    /// The claim that catches everybody. Keycloak publishes <c>roles</c>, Pocket ID and Entra
    /// publish <c>groups</c>, and reading the hardcoded one leaves every caller role-less while
    /// their token is perfectly valid.
    /// </summary>
    [Test]
    public async Task Roles_are_read_from_the_configured_claim()
    {
        await using var app = await StartAsync(roleClaim: "groups", roles: ["gatekeeper"]);
        var account = await Account.RegisterAsync(app);

        // The token carries it under groups and nowhere else, so anything reading a different claim
        // type reads nothing at all rather than reading it late.
        await Assert.That(account.Claims().String("groups")).IsEqualTo("gatekeeper");
        await Assert.That(account.Claims().Has("roles")).IsFalse();

        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(body.Strings("roles")).IsEquivalentTo(new[] { "gatekeeper" });
        await Assert.That(body.Bool("gatekeeper")).IsTrue();
    }

    [Test]
    public async Task Roles_fall_back_to_the_dotnet_claim_type_for_a_principal_from_elsewhere()
    {
        await using var app = await StartAsync();

        var body = await (await app.Client.Get("/test/current-user/dotnet-roles")).Json();

        await Assert.That(body.Strings("roles")).IsEquivalentTo(new[] { "gatekeeper" });
        await Assert.That(body.Bool("gatekeeper")).IsTrue();
    }

    [Test]
    public async Task FindClaim_reads_a_claim_type_that_has_no_property_of_its_own()
    {
        await using var app = await StartAsync();
        var account = await Account.RegisterAsync(app, "ada");

        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(body.String("userName")).IsEqualTo("ada");
        await Assert.That(body.Has("absent")).IsFalse();
    }

    [Test]
    public async Task A_token_carrying_no_roles_answers_an_empty_list()
    {
        await using var app = await StartAsync();
        var account = await Account.RegisterAsync(app);

        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(body.Names()).Contains("roles");
        await Assert.That(body.Strings("roles")).IsEmpty();
        await Assert.That(body.Bool("gatekeeper")).IsFalse();
    }

    [Test]
    public async Task An_anonymous_request_carries_no_roles_and_no_claims()
    {
        await using var app = await StartAsync(roles: ["gatekeeper"]);

        var body = await (await app.Client.Get("/test/current-user/open")).Json();

        await Assert.That(body.Names()).Contains("roles");
        await Assert.That(body.Strings("roles")).IsEmpty();
        await Assert.That(body.Bool("gatekeeper")).IsFalse();
        await Assert.That(body.Has("userName")).IsFalse();
    }
}
