using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Where the endpoints land, and what happens when they land twice.
/// </summary>
/// <remarks>
/// Mapping the same endpoints into two route groups is the ordinary shape of path-segment API
/// versioning, and it used to make the routing matcher unbuildable. The host started clean, logged
/// <c>Application started</c> and passed a startup health check - then answered 500 on <b>every</b>
/// route in the application from the first request onwards, because the matcher is built lazily and
/// could not be built at all.
/// </remarks>
public class EndpointMappingTests
{
    private static void MapTwoVersions(IEndpointRouteBuilder endpoints)
    {
        var v1 = endpoints.MapGroup("/api/v1");
        v1.MapToamaisutaaPasswordEndpoints("V1");
        v1.MapToamaisutaaTwoFactorEndpoints("V1");
        v1.MapToamaisutaaTrustedDeviceEndpoints("V1");

        var v2 = endpoints.MapGroup("/api/v2");
        v2.MapToamaisutaaPasswordEndpoints("V2");
        v2.MapToamaisutaaTwoFactorEndpoints("V2");
        v2.MapToamaisutaaTrustedDeviceEndpoints("V2");
    }

    [Test]
    public async Task The_same_endpoints_map_into_two_groups_and_every_route_still_answers()
    {
        await using var app = await TestApp.StartAsync(MapTwoVersions);

        // The root mapping, which the collision used to take down along with everything else.
        var root = await app.Client.PostJson("/auth/login", new { identifier = "nobody", password = "wrong" });
        await Assert.That(root.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await root.Json()).String("error")).IsEqualTo("invalid_grant");

        foreach (var prefix in new[] { "/api/v1", "/api/v2" })
        {
            var response = await app.Client.PostJson($"{prefix}/auth/login", new { identifier = "nobody", password = "wrong" });

            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
            await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
        }
    }

    [Test]
    public async Task A_group_serves_a_whole_working_sign_in()
    {
        await using var app = await TestApp.StartAsync(MapTwoVersions);

        var registered = await app.Client.PostJson(
            "/api/v2/auth/register",
            new { userName = "grace", email = "grace@example.com", password = "correct horse battery staple" });

        await Assert.That(registered.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var token = (await registered.Json()).String("access_token")!;
        var devices = await app.Client.Get("/api/v1/auth/devices", token);

        // Registered under v2, read under v1 - the same application, so the token works on both.
        await Assert.That(devices.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// The trusted device prefix composes onto the local login one, the way /2fa does. It used to
    /// be a full path with /auth baked in, so moving LocalLogin left the device endpoints behind.
    /// </summary>
    [Test]
    public async Task Moving_the_local_login_prefix_moves_the_two_factor_and_device_endpoints_with_it()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:EndpointPrefix"] = "/identity");

        var registered = await app.Client.PostJson(
            "/identity/register",
            new { userName = "ada", email = "ada@example.com", password = "correct horse battery staple" });

        await Assert.That(registered.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var token = (await registered.Json()).String("access_token")!;

        await Assert.That((await app.Client.Get("/identity/2fa", token)).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await app.Client.Get("/identity/devices", token)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        // And nothing is left behind at the old prefix.
        await Assert.That((await app.Client.Get("/auth/devices", token)).StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task The_configuration_endpoint_serves_its_own_shape_and_takes_a_route()
    {
        await using var app = await TestApp.StartAsync(endpoints => endpoints.MapToamaisutaaConfiguration("/api/config", "Alt"));

        var body = await (await app.Client.Get("/api/config")).Json();

        await Assert.That(body.Names()).IsEquivalentTo(new[]
        {
            "authority", "clientId", "redirectUri", "postLogoutRedirectUri", "scope",
        });
    }
}
