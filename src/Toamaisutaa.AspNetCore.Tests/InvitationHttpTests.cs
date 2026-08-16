using System.Net;

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
        var admin = await Account.RegisterAsync(app, "admin");

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
        var admin = await Account.RegisterAsync(app, "admin");
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
        var admin = await Account.RegisterAsync(app, "admin");

        var create = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        await Assert.That(create.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }
}
