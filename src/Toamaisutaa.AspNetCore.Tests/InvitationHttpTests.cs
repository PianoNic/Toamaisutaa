using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// <c>/auth/invitations</c> and <c>/auth/invitations/complete</c> - the invariant that matters here:
/// no response from either ever carries the invitation token, only <c>IInvitationNotifier</c> ever
/// sees it.
/// </summary>
public class InvitationHttpTests
{
    [Test]
    public async Task Creating_an_invitation_never_returns_the_token()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var response = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var body = await response.Json();
        await Assert.That(body.Names()).DoesNotContain("token");
        await Assert.That(body.String("email")).IsEqualTo("invited@example.com");

        await Assert.That(app.IssuedInvitations.Count).IsEqualTo(1);
        await Assert.That(app.IssuedInvitations[0].Token).IsNotEmpty();
    }

    [Test]
    public async Task Creating_an_invitation_requires_authentication()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Completing_an_invitation_signs_in_the_chosen_account()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        var token = app.IssuedInvitations.Single().Token;

        var complete = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token, userName = "invited", password = "correct horse battery" });

        await Assert.That(complete.StatusCode).IsEqualTo(HttpStatusCode.Created);
        var body = await complete.Json();
        await Assert.That(body.String("access_token")).IsNotNull();

        var login = await app.Client.PostJson("/auth/login", new { identifier = "invited", password = "correct horse battery" });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Completing_an_invitation_with_an_unknown_token_fails()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = "not-a-real-token", userName = "invited", password = "correct horse battery" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task Invitation_endpoints_are_not_mapped_without_a_notifier_registered()
    {
        await using var app = await TestApp.StartAsync(includeInvitationNotifier: false);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var create = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    // Reserving an account for an address of the caller's choosing is administration, not something
    // any signed-in account may do.
    [Test]
    public async Task Creating_an_invitation_is_refused_for_a_caller_without_the_admin_role()
    {
        await using var app = await TestApp.StartAsync();
        var mallory = await Account.RegisterAsync(app, "mallory");

        var response = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, mallory.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(app.IssuedInvitations).IsEmpty();
    }

    // Only the endpoint that issues a token needs the admin policy. Completing one is done by the
    // invited person, and the invitation may have been created by a worker rather than over HTTP.
    [Test]
    public async Task Only_the_issuing_endpoint_disappears_without_an_admin_role_configured()
    {
        await using var app = await TestApp.StartAsync(includeAdminRole: false);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var create = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        var complete = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = "not-a-real-token", userName = "invited", password = "correct horse battery" });

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(complete.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    // 502 rather than 500, and nothing reserved: the row and its token are rolled back, because
    // nothing here looks for an existing reservation and a retry would otherwise make a second one.
    [Test]
    public async Task A_failing_invitation_notifier_reserves_nothing()
    {
        await using var app = await TestApp.StartAsync(
            configureServices: services => services.AddSingleton<IInvitationNotifier>(new ThrowingInvitationNotifier()));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var response = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadGateway);

        var body = await response.Json();
        await Assert.That(body.String("error")).IsEqualTo("notification_failed");
        await Assert.That(body.Names()).DoesNotContain("token");

        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();

        await Assert.That(await db.Users.AsNoTracking().CountAsync(user => user.Email == "invited@example.com")).IsEqualTo(0);

        // Not merely "no live token": the row goes with the user it was issued for, which is the
        // cascade doing it rather than anything this flow writes.
        await Assert.That(await db.InvitationTokens.AsNoTracking().CountAsync()).IsEqualTo(0);
    }

    private sealed class ThrowingInvitationNotifier : IInvitationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the mail server is down");
    }
}
