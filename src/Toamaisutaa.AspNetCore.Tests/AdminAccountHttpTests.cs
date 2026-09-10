using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// <c>/auth/users</c> and <c>/auth/users/{userId}/password</c> - provisioning on someone else's
/// behalf. The invariant that matters here: no response from either ever carries a password, typed
/// or generated - it only ever reaches <c>IAdminPasswordIssuedNotifier</c>, in process.
/// </summary>
/// <remarks>
/// The second invariant is who may call them. They take the account from the route, so an ordinary
/// signed-in caller reaching them is a full takeover of any account, and for a while one could:
/// they carried the default policy, which is nothing but "authenticated".
/// </remarks>
public class AdminAccountHttpTests
{
    [Test]
    public async Task Creating_a_user_with_a_chosen_password_never_returns_it()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var response = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = "newteacher@example.com", password = "a chosen password" },
            admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var body = await response.Json();
        await Assert.That(body.Names()).DoesNotContain("password");
        await Assert.That(body.String("userName")).IsEqualTo("newteacher");

        await Assert.That(app.IssuedPasswords.Count).IsEqualTo(1);
        await Assert.That(app.IssuedPasswords[0].Password).IsEqualTo("a chosen password");
    }

    [Test]
    public async Task Creating_a_user_with_no_password_generates_one_that_signs_in()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var response = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = "newteacher@example.com", password = (string?)null },
            admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var generated = app.IssuedPasswords.Single().Password;

        var login = await app.Client.PostJson("/auth/login", new { identifier = "newteacher", password = generated });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Creating_a_user_requires_authentication()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson("/auth/users", new { userName = "newteacher", email = (string?)null, password = "whatever1" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Overwriting_a_password_ends_every_other_session_and_never_returns_it()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "target");

        var targetUserId = Account.DecodeClaims(target.AccessToken).String("sub")!;
        var targetRefreshToken = (await target.LoginAsync()).Json().Result.String("refresh_token")!;

        var response = await app.Client.PostJson(
            $"/auth/users/{targetUserId}/password",
            new { password = "brand new password" },
            admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(app.IssuedPasswords.Single().Password).IsEqualTo("brand new password");

        // The refresh token target held before the overwrite is dead - the same check
        // ChangingAPasswordEndsEveryOtherSession makes at the service layer, here over HTTP.
        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = targetRefreshToken });
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var login = await app.Client.PostJson("/auth/login", new { identifier = "target", password = "brand new password" });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Admin_endpoints_are_not_mapped_without_a_notifier_registered()
    {
        await using var app = await TestApp.StartAsync(includeAdminPasswordNotifier: false);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var create = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = (string?)null, password = "whatever1" },
            admin.AccessToken);

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    // ── Who may call them ──

    [Test]
    public async Task Creating_a_user_is_refused_for_a_caller_without_the_admin_role()
    {
        await using var app = await TestApp.StartAsync();
        var mallory = await Account.RegisterAsync(app, "mallory");

        var response = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = (string?)null, password = "a chosen password" },
            mallory.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(app.IssuedPasswords).IsEmpty();
    }

    // The takeover this endpoint used to allow, asserted as refused: an ordinary account posting a
    // password of its own choosing at somebody else's user id.
    [Test]
    public async Task Overwriting_a_password_is_refused_for_a_caller_without_the_admin_role()
    {
        await using var app = await TestApp.StartAsync();
        var mallory = await Account.RegisterAsync(app, "mallory");
        var target = await Account.RegisterAsync(app, "target");
        var targetUserId = Account.DecodeClaims(target.AccessToken).String("sub")!;

        var response = await app.Client.PostJson(
            $"/auth/users/{targetUserId}/password",
            new { password = "brand new password" },
            mallory.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(app.IssuedPasswords).IsEmpty();

        var stolen = await app.Client.PostJson("/auth/login", new { identifier = "target", password = "brand new password" });
        await Assert.That(stolen.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    // No admin role configured means no policy to put on them, and they are refused the wire rather
    // than mapped behind the default one - which is every account that ever registered.
    [Test]
    public async Task Admin_endpoints_are_not_mapped_without_an_admin_role_configured()
    {
        await using var app = await TestApp.StartAsync(includeAdminRole: false);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var targetUserId = Account.DecodeClaims(admin.AccessToken).String("sub")!;

        var create = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = (string?)null, password = "whatever1" },
            admin.AccessToken);

        var set = await app.Client.PostJson(
            $"/auth/users/{targetUserId}/password",
            new { password = "brand new password" },
            admin.AccessToken);

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(set.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    // ── A notifier that fails ──

    // 502 rather than 500, and the revocation happens either way. The SMTP notifier this package
    // ships throws on any relay failure, and the session teardown used to sit behind it.
    [Test]
    public async Task Overwriting_a_password_reports_a_failed_delivery_and_still_ends_every_session()
    {
        await using var app = await TestApp.StartAsync(
            configureServices: services => services.AddSingleton<IAdminPasswordIssuedNotifier>(new ThrowingAdminPasswordIssuedNotifier()));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "target");

        var targetUserId = Account.DecodeClaims(target.AccessToken).String("sub")!;
        var targetRefreshToken = (await target.LoginAsync()).Json().Result.String("refresh_token")!;

        var response = await app.Client.PostJson(
            $"/auth/users/{targetUserId}/password",
            new { password = "brand new password" },
            admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadGateway);

        var body = await response.Json();
        await Assert.That(body.String("error")).IsEqualTo("notification_failed");
        await Assert.That(body.String("error_description")).IsNotNull();
        await Assert.That(body.Names()).DoesNotContain("password");

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = targetRefreshToken });
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var login = await app.Client.PostJson("/auth/login", new { identifier = "target", password = "brand new password" });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    private sealed class ThrowingAdminPasswordIssuedNotifier : IAdminPasswordIssuedNotifier
    {
        public Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the mail server is down");
    }
}
