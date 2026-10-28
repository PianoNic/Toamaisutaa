using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Sign-in through another identity provider, driven the way a browser drives it: to the provider,
/// back to the callback, back to the client, then the exchange.
/// </summary>
public class ExternalLoginHttpTests
{
    private const string Provider = "test-idp";
    private const string ReturnUrl = "https://app.test/auth/callback";
    private const string NativeReturnUrl = "testapp://auth/callback";

    [Test]
    public async Task The_configured_providers_are_listed_for_anyone()
    {
        await using var app = await StartAsync(new FakeIdentityProvider());

        var response = await app.Client.Get("/auth/providers");
        var entry = (await response.Json()).EnumerateArray().Single(found => found.String("key") == Provider);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(entry.Names()).IsEquivalentTo(new[] { "key", "display_name", "icon_url" });
        await Assert.That(entry.String("key")).IsEqualTo(Provider);
        await Assert.That(entry.String("display_name")).IsEqualTo("Test Provider");
        await Assert.That(entry.String("icon_url")).IsEqualTo("https://idp.test/icon.svg");
    }

    [Test]
    public async Task Nothing_is_mapped_without_a_provider()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        // Authenticated, because an unmapped route meets the fallback policy first and answers 401.
        var response = await app.Client.Get("/auth/providers", account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task A_first_sign_in_creates_the_account_and_ends_in_local_tokens_that_say_fed()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp", "alice@idp.test", Name: "Alice"));
        var claims = Account.DecodeClaims(body.String("access_token")!);

        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(claims.String("iss")).IsEqualTo("toamaisutaa-tests");

        // Only fed: the provider's own amr claims mfa, and nothing here checked a second factor.
        await Assert.That(claims.Amr()).IsEquivalentTo(new[] { "fed" });

        var me = await (await app.Client.Get("/test/me", body.String("access_token"))).Json();
        await Assert.That(me.String("userName")).IsEqualTo("alice-at-idp");
    }

    /// <summary>The CLAUDE.md question for any new amr value: carried, recomputed or dropped.</summary>
    [Test]
    public async Task A_refreshed_token_still_says_fed()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp"));
        var refreshed = await (await app.Client.PostJson("/auth/refresh", new { refreshToken = body.String("refresh_token") })).Json();

        await Assert.That(Account.DecodeClaims(refreshed.String("access_token")!).Amr()).IsEquivalentTo(new[] { "fed" });
    }

    [Test]
    public async Task The_same_identity_signs_in_to_the_same_account_again()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var first = await SignInAsync(app, idp, new Person("alice-at-idp"));
        var second = await SignInAsync(app, idp, new Person("alice-at-idp"));

        await Assert.That(Account.DecodeClaims(second.String("access_token")!).String("sub"))
            .IsEqualTo(Account.DecodeClaims(first.String("access_token")!).String("sub"));
    }

    [Test]
    public async Task The_provider_is_redeemed_with_pkce_the_secret_and_the_registered_callback()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        await SignInAsync(app, idp, new Person("alice-at-idp"));
        var form = idp.TokenRequests.Single();

        await Assert.That(form["redirect_uri"]).IsEqualTo("http://localhost/auth/external/test-idp/callback");
        await Assert.That(form["client_secret"]).IsEqualTo(FakeIdentityProvider.ClientSecret);
        await Assert.That(form["code_verifier"]).IsNotEmpty();
    }

    [Test]
    public async Task The_client_s_state_comes_back_untouched()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var verifier = NewVerifier();

        var returned = await ReturnAsync(app, idp, new Person("alice-at-idp"), verifier, state: "opaque-123");

        await Assert.That(returned.GetLeftPart(UriPartial.Path)).IsEqualTo(ReturnUrl);
        await Assert.That(Query(returned, "state")).IsEqualTo("opaque-123");
        await Assert.That(Query(returned, "code")).IsNotNull();
    }

    [Test]
    public async Task A_native_app_gets_its_code_on_its_own_scheme()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var returned = await ReturnAsync(app, idp, new Person("alice-at-idp"), NewVerifier(), returnUrl: NativeReturnUrl);

        await Assert.That(returned.Scheme).IsEqualTo("testapp");
        await Assert.That(Query(returned, "code")).IsNotNull();
    }

    [Test]
    public async Task The_exchange_needs_the_verifier_and_a_wrong_one_spends_the_code()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var verifier = NewVerifier();

        var code = Query(await ReturnAsync(app, idp, new Person("alice-at-idp"), verifier), "code")!;

        var wrong = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = NewVerifier() });
        var right = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await wrong.Json()).String("error")).IsEqualTo("invalid_grant");
        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_code_is_exchanged_once()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var verifier = NewVerifier();

        var code = Query(await ReturnAsync(app, idp, new Person("alice-at-idp"), verifier), "code")!;

        var first = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });
        var second = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        await Assert.That(first.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(second.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_code_past_its_lifetime_is_refused()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var verifier = NewVerifier();

        var code = Query(await ReturnAsync(app, idp, new Person("alice-at-idp"), verifier), "code")!;
        app.Time.Advance(TimeSpan.FromMinutes(3));

        var response = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    [Arguments("https://app.test/auth/callback/../elsewhere")]
    [Arguments("https://app.test/auth/callback?next=https://evil.test")]
    [Arguments("https://evil.test/auth/callback")]
    [Arguments("")]
    public async Task Only_an_allowed_return_url_starts_a_sign_in(string returnUrl)
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var response = await app.Client.GetAsync(StartPath(NewVerifier(), returnUrl));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(response.Headers.Location).IsNull();
    }

    [Test]
    public async Task A_sign_in_without_an_s256_challenge_is_refused()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var missing = await app.Client.GetAsync($"/auth/external/{Provider}/start?returnUrl={Uri.EscapeDataString(ReturnUrl)}");
        var plain = await app.Client.GetAsync(
            $"/auth/external/{Provider}/start?returnUrl={Uri.EscapeDataString(ReturnUrl)}&codeChallenge={Challenge(NewVerifier())}&codeChallengeMethod=plain");

        await Assert.That(missing.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(plain.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task An_unknown_provider_is_not_found()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var response = await app.Client.GetAsync($"/auth/external/nobody/start?returnUrl={Uri.EscapeDataString(ReturnUrl)}&codeChallenge={Challenge(NewVerifier())}&codeChallengeMethod=S256");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task A_provider_answer_is_accepted_once()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var authorize = (await app.Client.GetAsync(StartPath(NewVerifier()))).Headers.Location!.ToString();
        var callback = PathAndQuery(idp.Authorize(authorize, new Person("alice-at-idp")));

        var first = await app.Client.GetAsync(callback);
        var replay = await app.Client.GetAsync(callback);

        await Assert.That(first.StatusCode).IsEqualTo(HttpStatusCode.Redirect);
        await Assert.That(replay.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(replay.Headers.Location).IsNull();
    }

    [Test]
    public async Task An_answer_to_no_sign_in_begun_here_is_refused_without_a_redirect()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var response = await app.Client.GetAsync($"/auth/external/{Provider}/callback?code=anything&state=made-up");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_request");
    }

    [Test]
    public async Task A_refusal_at_the_provider_comes_back_as_access_denied()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var authorize = (await app.Client.GetAsync(StartPath(NewVerifier()))).Headers.Location!;
        var state = QueryHelpers.ParseQuery(authorize.Query)["state"].ToString();

        var response = await app.Client.GetAsync($"/auth/external/{Provider}/callback?error=access_denied&state={state}");

        await Assert.That(Query(response.Headers.Location!, "error")).IsEqualTo("access_denied");
        await Assert.That(Query(response.Headers.Location!, "code")).IsNull();
    }

    [Test]
    public async Task An_id_token_minted_for_another_sign_in_is_refused() =>
        await RefusedAsync(new Tamper { Nonce = "someone-else-s" });

    [Test]
    public async Task An_id_token_for_another_client_is_refused() =>
        await RefusedAsync(new Tamper { Audience = "another-client" });

    [Test]
    public async Task An_id_token_from_another_issuer_is_refused() =>
        await RefusedAsync(new Tamper { Issuer = "https://evil.test" });

    [Test]
    public async Task An_id_token_not_signed_by_the_provider_is_refused() =>
        await RefusedAsync(new Tamper { ForeignKey = true });

    [Test]
    public async Task An_expired_id_token_is_refused() =>
        await RefusedAsync(new Tamper { Expired = true });

    [Test]
    public async Task A_multi_tenant_issuer_template_accepts_the_token_s_own_tenant()
    {
        var idp = new FakeIdentityProvider(tenant: "tenant-a");
        await using var app = await StartAsync(idp);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp"));

        await Assert.That(body.String("access_token")).IsNotNull();
    }

    [Test]
    public async Task A_multi_tenant_issuer_template_refuses_an_issuer_for_another_tenant()
    {
        var idp = new FakeIdentityProvider(tenant: "tenant-a");
        await using var app = await StartAsync(idp);

        var returned = await ReturnAsync(app, idp, new Person("alice-at-idp"), NewVerifier(), tamper: new Tamper { Issuer = $"{FakeIdentityProvider.Authority}/tenant-b/v2.0" });

        await Assert.That(Query(returned, "error")).IsEqualTo("external_login_failed");
    }

    [Test]
    public async Task By_default_a_provider_s_verified_address_is_not_put_in_the_token()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp", "alice@idp.test", EmailVerified: true));

        await Assert.That(Account.DecodeClaims(body.String("access_token")!).Has("email")).IsFalse();
    }

    [Test]
    public async Task A_trusted_provider_s_verified_address_is_in_the_token_and_survives_refresh()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, Trusting);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp", "alice@idp.test", EmailVerified: true));
        var refreshed = await (await app.Client.PostJson("/auth/refresh", new { refreshToken = body.String("refresh_token") })).Json();

        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("email")).IsEqualTo("alice@idp.test");
        await Assert.That(Account.DecodeClaims(refreshed.String("access_token")!).String("email")).IsEqualTo("alice@idp.test");
    }

    [Test]
    public async Task A_trusted_provider_s_unverified_address_is_not_in_the_token()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, Trusting);

        var body = await SignInAsync(app, idp, new Person("alice-at-idp", "alice@idp.test", EmailVerified: false));

        await Assert.That(Account.DecodeClaims(body.String("access_token")!).Has("email")).IsFalse();
    }

    [Test]
    public async Task An_address_the_provider_stops_vouching_for_leaves_the_token()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, Trusting);

        await SignInAsync(app, idp, new Person("alice-at-idp", "alice@idp.test", EmailVerified: true));
        var later = await SignInAsync(app, idp, new Person("alice-at-idp", "alice@elsewhere.test", EmailVerified: false));

        await Assert.That(Account.DecodeClaims(later.String("access_token")!).Has("email")).IsFalse();
    }

    [Test]
    public async Task An_address_verified_here_wins_over_a_provider_s()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, Trusting);
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        await LinkAsync(app, idp, account, new Person("ada-at-idp", "ada.elsewhere@idp.test", EmailVerified: true), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        var body = await SignInAsync(app, idp, new Person("ada-at-idp", "ada.elsewhere@idp.test", EmailVerified: true));

        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("email")).IsEqualTo(account.Email);
    }

    private static void Trusting(Dictionary<string, string?> settings) =>
        settings[$"ExternalLogin:Providers:{Provider}:TrustEmailVerified"] = "true";

    [Test]
    public async Task With_sign_up_off_a_stranger_is_turned_away()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, settings => settings[$"ExternalLogin:Providers:{Provider}:AllowSignUp"] = "false");

        var returned = await ReturnAsync(app, idp, new Person("stranger"), NewVerifier());

        await Assert.That(Query(returned, "error")).IsEqualTo("account_not_found");
        await Assert.That(Query(returned, "code")).IsNull();
    }

    [Test]
    public async Task An_address_an_account_already_holds_is_not_joined_by_default()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var owner = await Account.RegisterAsync(app, "owner");

        var returned = await ReturnAsync(app, idp, new Person("someone-at-idp", owner.Email), NewVerifier());

        await Assert.That(Query(returned, "error")).IsEqualTo("account_exists");
    }

    [Test]
    public async Task Opted_in_a_verified_address_joins_the_account_that_holds_it()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, settings => settings[$"ExternalLogin:Providers:{Provider}:LinkByVerifiedEmail"] = "true");
        var owner = await Account.RegisterAsync(app, "owner");

        var body = await SignInAsync(app, idp, new Person("owner-at-idp", owner.Email, EmailVerified: true));

        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("sub")).IsEqualTo(owner.Claims().String("sub"));
    }

    [Test]
    public async Task Opted_in_an_unverified_address_still_joins_nothing()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, settings => settings[$"ExternalLogin:Providers:{Provider}:LinkByVerifiedEmail"] = "true");
        var owner = await Account.RegisterAsync(app, "owner");

        var returned = await ReturnAsync(app, idp, new Person("owner-at-idp", owner.Email, EmailVerified: false), NewVerifier());

        await Assert.That(Query(returned, "error")).IsEqualTo("account_exists");
    }

    [Test]
    public async Task An_account_with_a_second_factor_is_asked_for_it_and_ends_with_fed_and_otp()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, code = NextCode(app, account) });

        var exchanged = await SignInAsync(app, idp, new Person("ada-at-idp"));

        await Assert.That(exchanged.Bool("two_factor_required")).IsTrue();
        await Assert.That(exchanged.Has("access_token")).IsFalse();

        app.Time.AdvanceToNextTotpStep();

        var verified = await (await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge = exchanged.String("challenge"), code = Totp.Code(account.Secret!, app.Time.Now) })).Json();

        await Assert.That(Account.DecodeClaims(verified.String("access_token")!).Amr()).IsEquivalentTo(new[] { "fed", "otp", "mfa" });
    }

    [Test]
    public async Task A_disabled_account_cannot_exchange_its_code()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var first = await SignInAsync(app, idp, new Person("alice-at-idp"));
        var userId = Account.DecodeClaims(first.String("access_token")!).String("sub");
        await app.Client.PostEmpty($"/auth/users/{userId}/disable", admin.AccessToken);

        var verifier = NewVerifier();
        var code = Query(await ReturnAsync(app, idp, new Person("alice-at-idp"), verifier), "code")!;
        var response = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_password_change_between_the_provider_and_the_exchange_refuses_it()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);
        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        var verifier = NewVerifier();
        var code = Query(await ReturnAsync(app, idp, new Person("ada-at-idp"), verifier), "code")!;

        await app.Client.PostJson("/auth/password", new { currentPassword = account.Password, newPassword = "a different passphrase" }, account.AccessToken);

        var response = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_signed_in_user_links_a_provider_and_then_signs_in_with_it()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);

        var returned = await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });
        var body = await SignInAsync(app, idp, new Person("ada-at-idp"));

        await Assert.That(Query(returned, "linked")).IsEqualTo(Provider);
        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("sub")).IsEqualTo(account.Claims().String("sub"));
    }

    [Test]
    public async Task Linking_needs_the_password_of_an_account_that_has_one()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);

        var missing = await app.Client.PostJson($"/auth/external/{Provider}/link", new { returnUrl = ReturnUrl }, account.AccessToken);
        var wrong = await app.Client.PostJson($"/auth/external/{Provider}/link", new { returnUrl = ReturnUrl, currentPassword = "not it" }, account.AccessToken);

        await Assert.That(missing.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await wrong.Json()).Strings("errors")).IsNotEmpty();
    }

    [Test]
    public async Task Linking_an_account_with_a_second_factor_needs_a_code_not_the_password()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var response = await app.Client.PostJson($"/auth/external/{Provider}/link", new { returnUrl = ReturnUrl, currentPassword = account.Password }, account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task An_account_with_no_password_links_on_a_fresh_sign_in_only()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, settings => settings["ExternalLogin:LinkProofWindow"] = "00:01:00");

        var body = await SignInAsync(app, idp, new Person("alice-at-idp"));
        var token = body.String("access_token")!;

        var fresh = await app.Client.PostJson("/auth/external/second/link", new { returnUrl = ReturnUrl }, token);

        // Past the window, and inside the test host's clock skew, so the refreshed token is still accepted.
        app.Time.Advance(TimeSpan.FromMinutes(2));
        var refreshed = await (await app.Client.PostJson("/auth/refresh", new { refreshToken = body.String("refresh_token") })).Json();
        var stale = await app.Client.PostJson("/auth/external/second/link", new { returnUrl = ReturnUrl }, refreshed.String("access_token")!);

        await Assert.That(fresh.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await fresh.Json()).String("authorization_url")).StartsWith(FakeIdentityProvider.Authority);
        await Assert.That(stale.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task An_identity_linked_to_one_account_cannot_be_linked_to_another()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        await SignInAsync(app, idp, new Person("alice-at-idp"));
        var account = await Account.RegisterAsync(app);

        var returned = await LinkAsync(app, idp, account, new Person("alice-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        await Assert.That(Query(returned, "error")).IsEqualTo("linked_to_another_account");
        await Assert.That(Query(returned, "linked")).IsNull();
    }

    [Test]
    public async Task A_second_identity_at_the_same_provider_is_not_linked()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);
        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        var returned = await LinkAsync(app, idp, account, new Person("ada-again"), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        await Assert.That(Query(returned, "error")).IsEqualTo("provider_already_linked");
    }

    [Test]
    public async Task Linked_providers_are_listed()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var account = await Account.RegisterAsync(app);
        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });

        var entry = (await (await app.Client.Get("/auth/external/logins", account.AccessToken)).Json()).EnumerateArray().Single();

        await Assert.That(entry.Names()).IsEquivalentTo(new[] { "provider", "display_name", "created_at", "last_sign_in_at" });
        await Assert.That(entry.String("provider")).IsEqualTo(Provider);
        await Assert.That(entry.String("display_name")).IsEqualTo("Test Provider");
    }

    [Test]
    public async Task Unlinking_ends_every_session_and_the_identity_no_longer_signs_in()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp, settings => settings[$"ExternalLogin:Providers:{Provider}:AllowSignUp"] = "false");
        var account = await Account.RegisterAsync(app);
        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });
        var federated = await SignInAsync(app, idp, new Person("ada-at-idp"));

        var unlinked = await app.Client.Delete($"/auth/external/logins/{Provider}", new { currentPassword = account.Password }, account.AccessToken);

        // Read off the store as well, because the stamp moves too and refresh refuses on either alone.
        IReadOnlyList<ToamaisutaaRefreshToken> live;
        await using (var scope = app.Services.CreateAsyncScope())
            live = await scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>().ListActiveAsync(Guid.Parse(account.Claims().String("sub")!));

        var refresh = await app.Client.PostJson("/auth/refresh", new { refreshToken = federated.String("refresh_token") });
        var stale = await app.Client.Get("/auth/external/logins", account.AccessToken);
        var again = await ReturnAsync(app, idp, new Person("ada-at-idp"), NewVerifier());

        await Assert.That(unlinked.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(live).IsEmpty();
        await Assert.That(refresh.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(stale.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(Query(again, "error")).IsEqualTo("account_not_found");
    }

    [Test]
    public async Task The_last_way_into_an_account_cannot_be_unlinked()
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);
        var body = await SignInAsync(app, idp, new Person("alice-at-idp"));

        var response = await app.Client.Delete($"/auth/external/logins/{Provider}", body.String("access_token")!);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/external/logins", body.String("access_token"))).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await (await app.Client.Get("/auth/external/logins", body.String("access_token"))).Json()).GetArrayLength()).IsEqualTo(1);
    }

    [Test]
    public async Task Sign_in_link_and_unlink_are_audited()
    {
        var idp = new FakeIdentityProvider();
        var recorded = new List<AuthenticationEvent>();
        await using var app = await StartAsync(idp, configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var created = await SignInAsync(app, idp, new Person("alice-at-idp"));
        var account = await Account.RegisterAsync(app);
        await LinkAsync(app, idp, account, new Person("ada-at-idp"), new { returnUrl = ReturnUrl, currentPassword = account.Password });
        await app.Client.Delete($"/auth/external/logins/{Provider}", new { currentPassword = account.Password }, account.AccessToken);

        var aliceId = Guid.Parse(Account.DecodeClaims(created.String("access_token")!).String("sub")!);
        var adaId = Guid.Parse(account.Claims().String("sub")!);

        List<AuthenticationEvent> events;

        lock (recorded)
            events = [.. recorded];

        await Assert.That(events.OfType<AccountCreated>().Single(found => found.UserId == aliceId).Source).IsEqualTo("external-login");
        await Assert.That(events.OfType<ExternalLoginAuthenticated>().Single().ProviderKey).IsEqualTo(Provider);
        await Assert.That(events.OfType<ExternalLoginLinked>().Single().UserId).IsEqualTo(adaId);
        await Assert.That(events.OfType<ExternalLoginUnlinked>().Single().UserId).IsEqualTo(adaId);
        await Assert.That(events.OfType<SignInSucceeded>().Single(found => found.UserId == aliceId).AuthenticationMethods).IsEquivalentTo(new[] { "fed" });
    }

    [Test]
    public async Task Startup_refuses_a_return_url_that_is_plain_http_off_localhost()
    {
        var started = async () =>
        {
            await using var app = await StartAsync(new FakeIdentityProvider(), settings => settings["ExternalLogin:AllowedReturnUrls:0"] = "http://app.test/callback");
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("AllowedReturnUrls");
    }

    [Test]
    public async Task Startup_refuses_providers_with_nowhere_to_return()
    {
        var started = async () =>
        {
            await using var app = await StartAsync(new FakeIdentityProvider(), settings =>
            {
                settings.Remove("ExternalLogin:AllowedReturnUrls:0");
                settings.Remove("ExternalLogin:AllowedReturnUrls:1");
            });
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("AllowedReturnUrls is empty");
    }

    [Test]
    public async Task Startup_refuses_a_plain_http_authority_outside_development()
    {
        var started = async () =>
        {
            await using var app = await StartAsync(new FakeIdentityProvider(), settings => settings[$"ExternalLogin:Providers:{Provider}:Authority"] = "http://idp.test");
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("must be https");
    }

    private static async Task RefusedAsync(Tamper tamper)
    {
        var idp = new FakeIdentityProvider();
        await using var app = await StartAsync(idp);

        var returned = await ReturnAsync(app, idp, new Person("alice-at-idp"), NewVerifier(), tamper: tamper);

        await Assert.That(Query(returned, "error")).IsEqualTo("external_login_failed");
        await Assert.That(Query(returned, "code")).IsNull();
    }

    private static Task<TestApp> StartAsync(
        FakeIdentityProvider idp,
        Action<Dictionary<string, string?>>? configure = null,
        Action<IServiceCollection>? configureServices = null) =>
        TestApp.StartAsync(
            configure: settings =>
            {
                foreach (var key in new[] { Provider, "second" })
                {
                    settings[$"ExternalLogin:Providers:{key}:Authority"] = FakeIdentityProvider.Authority;
                    settings[$"ExternalLogin:Providers:{key}:ClientId"] = FakeIdentityProvider.ClientId;
                    settings[$"ExternalLogin:Providers:{key}:ClientSecret"] = FakeIdentityProvider.ClientSecret;
                }

                settings[$"ExternalLogin:Providers:{Provider}:DisplayName"] = "Test Provider";
                settings[$"ExternalLogin:Providers:{Provider}:IconUrl"] = "https://idp.test/icon.svg";
                settings[$"ExternalLogin:Providers:{Provider}:AllowSignUp"] = "true";
                settings["ExternalLogin:AllowedReturnUrls:0"] = ReturnUrl;
                settings["ExternalLogin:AllowedReturnUrls:1"] = NativeReturnUrl;

                configure?.Invoke(settings);
            },
            configureServices: services =>
            {
                services.AddHttpClient(ToamaisutaaDefaults.ExternalLoginHttpClientName).ConfigurePrimaryHttpMessageHandler(() => idp);
                configureServices?.Invoke(services);
            });

    private static async Task<System.Text.Json.JsonElement> SignInAsync(TestApp app, FakeIdentityProvider idp, Person person)
    {
        var verifier = NewVerifier();
        var code = Query(await ReturnAsync(app, idp, person, verifier), "code")
            ?? throw new InvalidOperationException("The sign-in came back without a code.");

        var response = await app.Client.PostJson("/auth/external/exchange", new { code, codeVerifier = verifier });

        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Exchange failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        return await response.Json();
    }

    /// <summary>Start, the provider, the callback: where the browser lands at the end.</summary>
    private static async Task<Uri> ReturnAsync(
        TestApp app,
        FakeIdentityProvider idp,
        Person person,
        string verifier,
        string returnUrl = ReturnUrl,
        string? state = null,
        Tamper tamper = default)
    {
        var start = await app.Client.GetAsync(StartPath(verifier, returnUrl, state));

        if (start.StatusCode != HttpStatusCode.Redirect)
            throw new InvalidOperationException($"Start failed: {start.StatusCode} {await start.Content.ReadAsStringAsync()}");

        return await CallbackAsync(app, idp.Authorize(start.Headers.Location!.ToString(), person, tamper));
    }

    private static async Task<Uri> LinkAsync(TestApp app, FakeIdentityProvider idp, Account account, Person person, object body)
    {
        var response = await app.Client.PostJson($"/auth/external/{Provider}/link", body, account.AccessToken);

        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Link failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        return await CallbackAsync(app, idp.Authorize((await response.Json()).String("authorization_url")!, person));
    }

    private static async Task<Uri> CallbackAsync(TestApp app, string callbackUrl)
    {
        var response = await app.Client.GetAsync(PathAndQuery(callbackUrl));

        if (response.StatusCode != HttpStatusCode.Redirect)
            throw new InvalidOperationException($"Callback failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        return response.Headers.Location!;
    }

    private static string StartPath(string verifier, string returnUrl = ReturnUrl, string? state = null) =>
        QueryHelpers.AddQueryString($"/auth/external/{Provider}/start", new Dictionary<string, string?>
        {
            ["returnUrl"] = returnUrl,
            ["codeChallenge"] = Challenge(verifier),
            ["codeChallengeMethod"] = "S256",
            ["state"] = state,
        }.Where(pair => pair.Value is not null).ToDictionary());

    private static string PathAndQuery(string url) => new Uri(url).PathAndQuery;

    private static string? Query(Uri url, string name) =>
        QueryHelpers.ParseQuery(url.Query).TryGetValue(name, out var value) ? value.ToString() : null;

    private static string NewVerifier() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    /// <summary>RFC 7636 4.2, written out here rather than borrowed from the package.</summary>
    private static string Challenge(string verifier) => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static string NextCode(TestApp app, Account account)
    {
        app.Time.AdvanceToNextTotpStep();
        return Totp.Code(account.Secret!, app.Time.Now);
    }

    private sealed class RecordingSink(List<AuthenticationEvent> recorded) : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
        {
            lock (recorded)
                recorded.Add(authenticationEvent);

            return Task.CompletedTask;
        }
    }
}
