using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The session endpoints over the wire: what the list says, and what a revoke actually ends.
/// </summary>
/// <remarks>
/// Every assertion about a session being over goes through <c>/auth/refresh</c> rather than through
/// the list. A revoke that removed a row from a list and left the refresh token working would pass
/// a list-only test while leaving the session alive, which is the one thing this feature exists to
/// prevent.
/// </remarks>
public class SessionHttpTests
{
    /// <summary>Signs in again and hands back that session's tokens. Registration already
    /// established one, so the account starts with a session of its own.</summary>
    private static async Task<JsonElement> SignInAgainAsync(TestApp app, Account account, string? userAgent = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new { identifier = account.UserName, password = account.Password }),
        };

        if (userAgent is not null)
            request.Headers.UserAgent.ParseAdd(userAgent);

        return await (await app.Client.SendAsync(request)).Json();
    }

    private static Task<HttpResponseMessage> RefreshAsync(TestApp app, JsonElement tokens) =>
        app.Client.PostJson("/auth/refresh", new { refreshToken = tokens.String("refresh_token") });

    /// <summary>The listed entry for the session a sign-in response belongs to, found by the
    /// <c>toa_sid</c> on its access token.</summary>
    private static JsonElement Entry(JsonElement listed, JsonElement tokens)
    {
        var sid = Account.DecodeClaims(tokens.String("access_token")!).String("toa_sid");

        return listed.EnumerateArray().Single(session => session.String("id") == sid);
    }

    [Test]
    public async Task The_session_list_names_the_fields_a_client_reads()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        await Assert.That(listed[0].Names()).IsEquivalentTo(new[]
        {
            "id", "userAgent", "ipAddress", "createdAt", "lastUsedAt", "expiresAt",
            "authenticationMethods", "isCurrent",
        });
    }

    [Test]
    public async Task The_list_marks_the_session_the_caller_is_on()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await SignInAgainAsync(app, account);

        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        await Assert.That(listed.GetArrayLength()).IsEqualTo(2);

        var current = listed.EnumerateArray().Where(session => session.GetProperty("isCurrent").GetBoolean()).ToList();

        await Assert.That(current).HasCount().EqualTo(1);
        await Assert.That(current[0].String("id")).IsEqualTo(account.Claims().String("toa_sid"));
    }

    [Test]
    public async Task The_list_reports_the_user_agent_the_sign_in_sent()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var second = await SignInAgainAsync(app, account, userAgent: "Toamaisutaa-Test/1.0");
        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        await Assert.That(Entry(listed, second).String("userAgent")).IsEqualTo("Toamaisutaa-Test/1.0");
    }

    /// <summary>
    /// The rule this package has broken three times: a value the token carries has to survive a
    /// rotation. Here it is the session's own description rather than a claim, and the failure is
    /// quieter - the list would simply forget where every session came from after one refresh.
    /// </summary>
    [Test]
    public async Task A_refresh_keeps_the_session_and_what_it_says_about_itself()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var second = await SignInAgainAsync(app, account, userAgent: "Toamaisutaa-Test/1.0");

        await RefreshAsync(app, second);

        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        // Same session id after the rotation, still describing where it came from.
        await Assert.That(Entry(listed, second).String("userAgent")).IsEqualTo("Toamaisutaa-Test/1.0");
    }

    /// <summary>
    /// The whole path for <c>LocalLogin:IpAddressStorage</c>: the endpoint reads the connection, the
    /// service truncates it, and the list hands back a network rather than an address.
    /// </summary>
    [Test]
    public async Task The_stored_address_is_truncated_to_the_network()
    {
        await using var app = await TestApp.StartAsync(remoteIpAddress: "203.0.113.42");
        var account = await Account.RegisterAsync(app);

        var second = await SignInAgainAsync(app, account);
        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();
        var entry = Entry(listed, second);

        await Assert.That(entry.String("ipAddress")).IsEqualTo("203.0.113.0/24");
    }

    [Test]
    public async Task No_address_is_stored_when_configuration_does_not_ask_for_one()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:IpAddressStorage"] = "None",
            remoteIpAddress: "203.0.113.42");

        var account = await Account.RegisterAsync(app);

        var second = await SignInAgainAsync(app, account);
        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        await Assert.That(Entry(listed, second).String("ipAddress")).IsNull();
    }

    [Test]
    public async Task Revoking_a_session_stops_its_refresh_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var second = await SignInAgainAsync(app, account);
        var sid = Account.DecodeClaims(second.String("access_token")!).String("toa_sid");

        var revoked = await app.Client.Delete($"/auth/sessions/{sid}", account.AccessToken);

        await Assert.That(revoked.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That((await RefreshAsync(app, second)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();
        await Assert.That(listed.GetArrayLength()).IsEqualTo(1);
    }

    /// <summary>404 for someone else's session and for one that never existed alike, or this
    /// endpoint becomes a way to discover another account's session ids.</summary>
    [Test]
    public async Task Revoking_a_session_that_is_not_the_caller_s_answers_404()
    {
        await using var app = await TestApp.StartAsync();
        var ada = await Account.RegisterAsync(app);
        var grace = await Account.RegisterAsync(app, "grace");

        var hers = grace.Claims().String("toa_sid");

        var response = await app.Client.Delete($"/auth/sessions/{hers}", ada.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);

        // And hers is untouched.
        var listed = await (await app.Client.Get("/auth/sessions", grace.AccessToken)).Json();
        await Assert.That(listed.GetArrayLength()).IsEqualTo(1);
    }

    [Test]
    public async Task Revoking_a_session_that_never_existed_answers_404()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.Delete($"/auth/sessions/{Guid.Empty}", account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task Signing_out_everywhere_else_keeps_the_calling_session_alive()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        // The session registration established is the one the caller is on; these two are elsewhere.
        var second = await SignInAgainAsync(app, account);
        var third = await SignInAgainAsync(app, account);

        var response = await app.Client.Delete("/auth/sessions", account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That((await RefreshAsync(app, second)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await RefreshAsync(app, third)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        // The caller is still signed in, which is the whole point of not calling it "sign out".
        var listed = await (await app.Client.Get("/auth/sessions", account.AccessToken)).Json();

        await Assert.That(listed.GetArrayLength()).IsEqualTo(1);
        await Assert.That(listed[0].String("id")).IsEqualTo(account.Claims().String("toa_sid"));
    }

    [Test]
    public async Task Signing_out_everywhere_else_leaves_another_account_alone()
    {
        await using var app = await TestApp.StartAsync();
        var ada = await Account.RegisterAsync(app);
        var grace = await Account.RegisterAsync(app, "grace");

        var hers = await SignInAgainAsync(app, grace);

        await app.Client.Delete("/auth/sessions", ada.AccessToken);

        // Her refresh token, not a count: a list that had stopped scoping to the caller would still
        // return two rows here, and the count alone would agree with the bug.
        await Assert.That((await RefreshAsync(app, hers)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// A token an identity provider issued carries no <c>toa_sid</c>, so there is no session of the
    /// caller's to mark or to spare. Listing still works - a user signed in through a provider may
    /// well have local sessions to end - and the list marks none of them current.
    /// </summary>
    /// <remarks>
    /// Minted rather than doctored, for the reason <c>StepUpHttpTests</c> mints one: editing a real
    /// token breaks its signature and the request never reaches the endpoint under test.
    /// </remarks>
    [Test]
    public async Task A_token_with_no_session_claim_lists_sessions_and_marks_none_of_them_current()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var sessionless = app.MintTokenWithoutSession(account.Claims().String("sub")!);

        var listed = await (await app.Client.Get("/auth/sessions", sessionless)).Json();

        await Assert.That(listed.GetArrayLength()).IsEqualTo(1);
        await Assert.That(listed[0].GetProperty("isCurrent").GetBoolean()).IsFalse();
    }

    [Test]
    public async Task The_session_endpoints_need_a_token()
    {
        await using var app = await TestApp.StartAsync();

        await Assert.That((await app.Client.Get("/auth/sessions")).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var revoke = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "/auth/sessions"));
        await Assert.That(revoke.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// The filter every endpoint in this group carries. A password change moves the security stamp,
    /// which is exactly the moment somebody is looking at their session list.
    /// </summary>
    [Test]
    public async Task A_token_whose_stamp_has_moved_answers_401_rather_than_500()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var stale = account.AccessToken;

        var changed = await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);

        await Assert.That(changed.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var response = await app.Client.Get("/auth/sessions", stale);

        var header = string.Join(' ', response.Headers.WwwAuthenticate.Select(value => value.ToString()));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(header).Contains("error=\"invalid_token\"");
    }
}
