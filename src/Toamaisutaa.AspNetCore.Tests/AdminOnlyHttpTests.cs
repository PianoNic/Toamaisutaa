using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Toamaisutaa.AspNetCore.Tests;

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

    /// <summary>An endpoint naming a policy of its own never consults the default or the fallback
    /// policy, so the admin requirement has to reach it some other way.</summary>
    [Test]
    public async Task An_endpoint_naming_its_own_policy_is_admin_only_too()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["Oidc:RequireAdminRoleGlobally"] = "true",
            mapExtra: endpoints => endpoints.MapGet("/test/named", () => "ok").RequireAuthorization("AnyoneSignedIn"),
            configureServices: services => services.AddAuthorization(options =>
                options.AddPolicy("AnyoneSignedIn", policy => policy.RequireAuthenticatedUser())));

        var ordinary = await Account.RegisterAsync(app);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await Assert.That((await app.Client.Get("/test/named", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That((await app.Client.Get("/test/named", admin.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>With RequireAuthenticatedUser off, admin-only used to switch off with it, silently.</summary>
    [Test]
    public async Task Admin_only_holds_with_RequireAuthenticatedUser_off()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings =>
            {
                settings["Oidc:RequireAdminRoleGlobally"] = "true";
                settings["Oidc:RequireAuthenticatedUser"] = "false";
            },
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
    }

    /// <summary>A blank role means no admin role, so the flag has nothing to require - rather than
    /// requiring a role nobody holds and forbidding every authorized request.</summary>
    [Test]
    public async Task A_blank_admin_role_does_not_lock_everyone_out()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings =>
            {
                settings["Oidc:RequireAdminRoleGlobally"] = "true";
                settings["Oidc:AdminRole"] = " ";
            },
            mapExtra: endpoints => endpoints.MapGet("/test/authorized", () => "ok").RequireAuthorization());

        var ordinary = await Account.RegisterAsync(app);

        await Assert.That((await app.Client.Get("/test/authorized", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Without_the_flag_a_signed_in_user_passes_plain_authorization()
    {
        await using var app = await TestApp.StartAsync(mapExtra: endpoints =>
            endpoints.MapGet("/test/authorized", () => "ok").RequireAuthorization());

        var ordinary = await Account.RegisterAsync(app);

        await Assert.That((await app.Client.Get("/test/authorized", ordinary.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }
}
