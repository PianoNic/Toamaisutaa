using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>These sign in rather than build the principal by hand, because the role claim type is
/// decided by the issuer and the bearer handler and a hand-built principal would agree with itself.</summary>
public class CurrentUserHttpTests
{
    private sealed class FixedRoleProvider(params string[] roles) : IUserRoleProvider
    {
        public Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>(roles);
    }

    /// <summary>Written out rather than read off the options, so a rename has to be made here too.</summary>
    private const string AdminPolicy = "Toamaisutaa.Admin";

    private static void MapCurrentUser(IEndpointRouteBuilder endpoints, bool mapAdmin)
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

        // Built by hand because the fallback under test is for principals this package's pipeline did not build.
        endpoints.MapGet("/test/current-user/dotnet-roles", (HttpContext context) =>
        {
            context.User = new ClaimsPrincipal(
                new ClaimsIdentity([new Claim(ClaimTypes.Role, "gatekeeper")], "TestScheme"));

            var currentUser = context.RequestServices.GetRequiredService<ICurrentUser>();

            return Results.Ok(new { roles = currentUser.Roles, gatekeeper = currentUser.IsInRole("gatekeeper") });
        })
        .AllowAnonymous();

        // A foreign registration's own role claim type, which has to be honoured with none of our
        // configuration bound.
        endpoints.MapGet("/test/current-user/named-role-type", (HttpContext context) =>
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("groups", "gatekeeper")],
                authenticationType: "TestScheme",
                nameType: ClaimTypes.Name,
                roleType: "groups"));

            var currentUser = context.RequestServices.GetRequiredService<ICurrentUser>();

            return Results.Ok(new
            {
                roles = currentUser.Roles,
                gatekeeper = currentUser.IsInRole("gatekeeper"),
                // What RequireRole resolves through, on the same principal in the same request.
                policy = context.User.IsInRole("gatekeeper"),
            });
        })
        .AllowAnonymous();

        endpoints.MapGet("/test/current-user/open", (ICurrentUser currentUser) => Results.Ok(new
        {
            roles = currentUser.Roles,
            gatekeeper = currentUser.IsInRole("gatekeeper"),
            userName = currentUser.FindClaim("preferred_username"),
        }))
        .AllowAnonymous();

        // Lets a test assert that the authorization layer and ICurrentUser agree on the same token.
        if (mapAdmin)
        {
            endpoints.MapGet("/test/current-user/admin", () => Results.Ok(new { admin = true }))
                .RequireAuthorization(AdminPolicy);
        }
    }

    private static Task<TestApp> StartAsync(
        string? roleClaim = null,
        string? adminRole = null,
        string? dotnetRoleClaim = null,
        params string[] roles) =>
        TestApp.StartAsync(
            endpoints => MapCurrentUser(endpoints, adminRole is not null),
            configure: settings =>
            {
                if (roleClaim is not null)
                    settings["Oidc:RoleClaim"] = roleClaim;

                if (adminRole is not null)
                    settings["Oidc:AdminRole"] = adminRole;
            },
            configureServices: services =>
            {
                services.AddSingleton<IUserRoleProvider>(new FixedRoleProvider(roles));

                if (dotnetRoleClaim is not null)
                    AddDotnetRoleClaim(services, dotnetRoleClaim);
            });

    /// <summary>Added at validation rather than minted, because the local issuer only emits roles under
    /// the configured claim, so no token this host signs can carry a WS-Federation-typed role.</summary>
    private static void AddDotnetRoleClaim(IServiceCollection services, string role) =>
        services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            options.Events ??= new JwtBearerEvents();

            // Chained, not replaced: OnTokenValidated is where the package enriches from userinfo.
            var enrich = options.Events.OnTokenValidated;

            options.Events.OnTokenValidated = async context =>
            {
                await enrich(context);

                if (context.Principal?.Identity is ClaimsIdentity identity)
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
            };
        });

    [Test]
    public async Task Roles_come_off_the_token_and_IsInRole_matches_ordinally()
    {
        await using var app = await StartAsync(roles: ["gatekeeper", "archivist"]);
        var account = await Account.RegisterAsync(app);

        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(body.Strings("roles")).IsEquivalentTo(new[] { "gatekeeper", "archivist" });
        await Assert.That(body.Bool("gatekeeper")).IsTrue();
        await Assert.That(body.Bool("stranger")).IsFalse();

        // Ordinal, as RequireRole is, or a role check would grant on a value authorization refuses.
        await Assert.That(body.Bool("cased")).IsFalse();
    }

    [Test]
    public async Task Roles_are_read_from_the_configured_claim()
    {
        await using var app = await StartAsync(roleClaim: "groups", roles: ["gatekeeper"]);
        var account = await Account.RegisterAsync(app);

        // Under groups and nowhere else, so reading any other claim type finds nothing.
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

    /// <summary>Reading <c>Oidc:RoleClaim</c> alone would report nothing for a caller <c>RequireRole</c>
    /// lets straight through.</summary>
    [Test]
    public async Task Roles_read_the_role_claim_type_a_foreign_registration_named()
    {
        await using var app = await StartAsync();

        var body = await (await app.Client.Get("/test/current-user/named-role-type")).Json();

        await Assert.That(body.Strings("roles")).IsEquivalentTo(new[] { "gatekeeper" });
        await Assert.That(body.Bool("gatekeeper")).IsTrue();
        await Assert.That(body.Bool("policy")).IsTrue();
    }

    /// <summary><c>RequireRole</c> resolves through the identity's role claim type, set to
    /// <c>Oidc:RoleClaim</c>, so a WS-Federation-typed role must not count in <c>IsInRole</c> either.</summary>
    [Test]
    public async Task A_dotnet_typed_role_claim_is_refused_by_the_admin_policy_and_by_IsInRole_alike()
    {
        await using var app = await StartAsync(adminRole: "gatekeeper", dotnetRoleClaim: "gatekeeper");
        var account = await Account.RegisterAsync(app);

        var admin = await app.Client.Get("/test/current-user/admin", account.AccessToken);
        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(admin.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(body.Strings("roles")).IsEmpty();
        await Assert.That(body.Bool("gatekeeper")).IsFalse();
    }

    /// <summary>The control for the test above, so its 403 is about the claim type rather than a policy
    /// nothing can satisfy.</summary>
    [Test]
    public async Task The_configured_role_claim_satisfies_the_admin_policy_and_IsInRole_alike()
    {
        await using var app = await StartAsync(adminRole: "gatekeeper", roles: ["gatekeeper"]);
        var account = await Account.RegisterAsync(app);

        var admin = await app.Client.Get("/test/current-user/admin", account.AccessToken);
        var body = await (await app.Client.Get("/test/current-user", account.AccessToken)).Json();

        await Assert.That(admin.StatusCode).IsEqualTo(HttpStatusCode.OK);
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
