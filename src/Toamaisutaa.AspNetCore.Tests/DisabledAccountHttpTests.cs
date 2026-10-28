using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class DisabledAccountHttpTests
{
    [Test]
    public async Task Disabling_refuses_the_password_ends_the_session_and_sends_nothing()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "departed");
        var refreshToken = (await (await target.LoginAsync()).Json()).String("refresh_token")!;

        var disabled = await app.Client.PostEmpty($"/auth/users/{UserId(target)}/disable", admin.AccessToken);

        await Assert.That(disabled.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await Refresh(app, refreshToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        // The mailbox is the departing user's, so nothing may go to it.
        await Assert.That(app.IssuedPasswords).IsEmpty();
        await Assert.That(app.IssuedMagicLinks).IsEmpty();
    }

    [Test]
    public async Task Enabling_lets_the_same_password_sign_in_again()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "returning");

        await app.Client.PostEmpty($"/auth/users/{UserId(target)}/disable", admin.AccessToken);
        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var enabled = await app.Client.PostEmpty($"/auth/users/{UserId(target)}/enable", admin.AccessToken);

        await Assert.That(enabled.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Revoking_sessions_ends_them_and_the_token_in_flight_but_keeps_the_password()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "compromised");
        var refreshToken = (await (await target.LoginAsync()).Json()).String("refresh_token")!;

        var revoked = await app.Client.PostEmpty($"/auth/users/{UserId(target)}/sessions/revoke", admin.AccessToken);

        await Assert.That(revoked.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That((await Refresh(app, refreshToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await app.Client.Get("/auth/sessions", target.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var again = await target.LoginAsync();
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(app.IssuedPasswords).IsEmpty();

        // The stamp alone refuses the old refresh token; only revoking the rows takes the session off
        // the list. Registration and the first login each started one; only this sign-in is left.
        var sessions = await app.Client.Get("/auth/sessions", (await again.Json()).String("access_token"));
        await Assert.That((await sessions.Json()).GetArrayLength()).IsEqualTo(1);
    }

    [Test]
    public async Task Only_an_admin_can_disable_and_an_unknown_id_is_not_found()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var other = await Account.RegisterAsync(app, "peer");
        var target = await Account.RegisterAsync(app, "victim");

        var byPeer = await app.Client.PostEmpty($"/auth/users/{UserId(target)}/disable", other.AccessToken);
        var unknown = await app.Client.PostEmpty($"/auth/users/{Guid.NewGuid()}/disable", admin.AccessToken);

        await Assert.That(byPeer.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    // The tests below set the flag alone, revoking nothing and leaving the stamp where it was, so each
    // one goes red only if its own check is missing rather than passing on the revocation.

    [Test]
    public async Task A_disabled_account_is_refused_the_right_password()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await FlagDisabledAsync(app, account);

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_disabled_account_cannot_refresh_a_session_it_already_holds()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var refreshToken = (await (await account.LoginAsync()).Json()).String("refresh_token")!;

        await FlagDisabledAsync(app, account);

        await Assert.That((await Refresh(app, refreshToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_disabled_account_is_refused_by_the_current_user_with_a_403_that_says_so()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await FlagDisabledAsync(app, account);

        var me = await app.Client.Get("/auth/sessions", account.AccessToken);

        await Assert.That(me.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That((await me.Json()).String("error")).IsEqualTo("account_disabled");
    }

    [Test]
    public async Task A_disabled_account_cannot_spend_a_magic_link_or_be_sent_one()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        var token = await account.RequestMagicLinkAsync();

        await FlagDisabledAsync(app, account);

        var spent = await app.Client.PostJson("/auth/magic-link/verify", new { token });
        await Assert.That(spent.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var sentBefore = app.IssuedMagicLinks.Count;
        await app.Client.PostJson("/auth/magic-link", new { email = account.Email });
        await Assert.That(app.IssuedMagicLinks.Count).IsEqualTo(sentBefore);
    }

    [Test]
    public async Task A_disabled_account_cannot_spend_a_reset_link_or_be_sent_one()
    {
        var issued = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(issued)));

        var account = await Account.RegisterAsync(app);
        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        var token = issued.Single();

        await FlagDisabledAsync(app, account);

        var reset = await app.Client.PostJson("/auth/password/reset", new { token, newPassword = "a different correct horse" });
        await Assert.That(reset.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        await Assert.That(issued.Count).IsEqualTo(1);
    }

    [Test]
    public async Task A_disabled_account_cannot_sign_in_with_a_passkey()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        await FlagDisabledAsync(app, account);

        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_second_factor_challenge_issued_before_disabling_cannot_finish_the_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge")!;

        await FlagDisabledAsync(app, account);
        app.Time.AdvanceToNextTotpStep();

        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_disabled_reservation_cannot_complete_its_invitation()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        var (userId, token) = app.IssuedInvitations.Single();

        await FlagDisabledAsync(app, userId);

        var completed = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token, userName = "invited", password = Account.DefaultPassword });

        await Assert.That(completed.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    private static Guid UserId(Account account) => Guid.Parse(account.Claims().String("sub")!);

    private static Task<HttpResponseMessage> Refresh(TestApp app, string refreshToken) =>
        app.Client.PostJson("/auth/refresh", new { refreshToken });

    private static Task FlagDisabledAsync(TestApp app, Account account) => FlagDisabledAsync(app, UserId(account));

    private static async Task FlagDisabledAsync(TestApp app, Guid userId)
    {
        await using var scope = app.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IUserStore>().SetDisabledAtAsync(userId, app.Time.Now);
    }
}
