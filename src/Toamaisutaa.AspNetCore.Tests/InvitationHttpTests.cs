using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

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
    public async Task Inviting_an_address_again_retires_the_earlier_link()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        var first = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = app.IssuedInvitations[0].Token, userName = "early", password = Account.DefaultPassword });

        var latest = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = app.IssuedInvitations[1].Token, userName = "invited", password = Account.DefaultPassword });

        await Assert.That(first.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(latest.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That(app.IssuedInvitations[1].UserId).IsEqualTo(app.IssuedInvitations[0].UserId);
    }

    [Test]
    public async Task A_revoked_invitation_cannot_be_completed()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);

        var revoked = await app.Client.PostJson("/auth/invitations/revoke", new { email = "invited@example.com" }, admin.AccessToken);
        var again = await app.Client.PostJson("/auth/invitations/revoke", new { email = "invited@example.com" }, admin.AccessToken);

        var complete = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = app.IssuedInvitations.Single().Token, userName = "invited", password = Account.DefaultPassword });

        await Assert.That(revoked.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(complete.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task Revoking_never_touches_an_account_that_was_completed()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var ada = await Account.RegisterAsync(app);

        var revoked = await app.Client.PostJson("/auth/invitations/revoke", new { email = ada.Email }, admin.AccessToken);

        await Assert.That(revoked.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That((await ada.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// A provider sync can move the user row's profile email, so the proven address is the one recorded on the token.
    /// </summary>
    [Test]
    public async Task Completing_verifies_the_address_the_invitation_went_to()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        var (reservedId, token) = app.IssuedInvitations.Single();

        await using (var scope = app.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserStore>().SetEmailAsync(reservedId, "ceo@example.com");

        await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token, userName = "invited", password = Account.DefaultPassword });

        var byInvited = await app.Client.PostJson("/auth/login", new { identifier = "invited@example.com", password = Account.DefaultPassword });
        var byRewritten = await app.Client.PostJson("/auth/login", new { identifier = "ceo@example.com", password = Account.DefaultPassword });

        await Assert.That(byInvited.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(byRewritten.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Completing_one_link_in_parallel_succeeds_once_and_never_500s()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        var token = app.IssuedInvitations.Single().Token;

        var attempts = await Task.WhenAll(Enumerable.Range(0, 8).Select(index =>
            app.Client.PostJson("/auth/invitations/complete", new { token, userName = $"invited{index}", password = Account.DefaultPassword })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.Created)).IsEqualTo(1);
        await Assert.That(attempts.Any(response => response.StatusCode == HttpStatusCode.InternalServerError)).IsFalse();
    }

    [Test]
    public async Task Revoking_an_invitation_is_for_administrators_only()
    {
        await using var app = await TestApp.StartAsync();
        var ordinary = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/invitations/revoke", new { email = "invited@example.com" }, ordinary.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
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

    [Test]
    public async Task Creating_an_invitation_is_refused_for_a_caller_without_the_admin_role()
    {
        await using var app = await TestApp.StartAsync();
        var mallory = await Account.RegisterAsync(app, "mallory");

        var response = await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, mallory.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(app.IssuedInvitations).IsEmpty();
    }

    // Completion stays mapped because the invitation may have been created by a worker rather than over HTTP.
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

    // Nothing looks for an existing reservation, so a retry after a kept row would make a second one.
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

        // The token row goes by cascade with its user, not by anything this flow writes.
        await Assert.That(await db.InvitationTokens.AsNoTracking().CountAsync()).IsEqualTo(0);
    }

    private sealed class ThrowingInvitationNotifier : IInvitationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the mail server is down");
    }
}
