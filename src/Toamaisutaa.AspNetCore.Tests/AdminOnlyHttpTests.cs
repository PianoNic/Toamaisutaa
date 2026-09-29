using System.Net;
using Microsoft.AspNetCore.Builder;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// <c>Oidc:RequireAdminRoleGlobally</c> promises an admin-only application. It used to set only the
/// fallback policy, which covers endpoints that say nothing - so any endpoint that did ask for
/// authorization, with a bare <c>[Authorize]</c>, let every signed-in user through.
/// </summary>
public class AdminOnlyHttpTests
{
    [Test]
    public async Task An_endpoint_asking_for_plain_authorization_is_admin_only_too()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["Oidc:RequireAdminRoleGlobally"] = "true",
            mapExtra: endpoints =>
            {
                endpoints.MapGet("/test/authorized", () => "ok").RequireAuthorization();
                endpoints.MapGet("/test/unmarked", () => "ok");
            });

        var ordinary = await Account.RegisterAsync(app);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await Assert.That((await app.Client.Get("/test/authorized", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That((await app.Client.Get("/test/unmarked", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.Forbidden);

        await Assert.That((await app.Client.Get("/test/authorized", admin.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await app.Client.Get("/test/unmarked", admin.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>Without the flag, a plain authorization requirement is still just "signed in".</summary>
    [Test]
    public async Task Without_the_flag_a_signed_in_user_passes_plain_authorization()
    {
        await using var app = await TestApp.StartAsync(mapExtra: endpoints =>
            endpoints.MapGet("/test/authorized", () => "ok").RequireAuthorization());

        var ordinary = await Account.RegisterAsync(app);

        await Assert.That((await app.Client.Get("/test/authorized", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }
}
