using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// <c>/auth/users</c> and <c>/auth/users/{userId}/password</c> - provisioning on someone else's
/// behalf. The invariant that matters here: no response from either ever carries a password, typed
/// or generated - it only ever reaches <c>IAdminPasswordIssuedNotifier</c>, in process.
/// </summary>
public class AdminAccountHttpTests
{
    [Test]
    public async Task Creating_a_user_with_a_chosen_password_never_returns_it()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, "admin");

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
        var admin = await Account.RegisterAsync(app, "admin");

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
        var admin = await Account.RegisterAsync(app, "admin");
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
        var admin = await Account.RegisterAsync(app, "admin");

        var create = await app.Client.PostJson(
            "/auth/users",
            new { userName = "newteacher", email = (string?)null, password = "whatever1" },
            admin.AccessToken);

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }
}
