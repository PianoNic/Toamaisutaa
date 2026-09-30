using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class PasskeyHttpTests
{
    [Test]
    public async Task Registering_a_passkey_returns_it_in_the_list()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var registered = await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, label: "work laptop");

        await Assert.That(registered.StatusCode).IsEqualTo(HttpStatusCode.Created);

        // No Location, because there is no per-passkey GET route for a client to follow.
        await Assert.That(registered.Headers.Contains("Location")).IsFalse();

        var created = await registered.Json();
        await Assert.That(created.String("label")).IsEqualTo("work laptop");
        await Assert.That(created.String("id")).IsNotNull();
        await Assert.That(created.Strings("transports")).IsEquivalentTo(new[] { "internal" });

        var listed = await app.Client.Get("/auth/passkeys", account.AccessToken);
        await Assert.That(listed.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var entries = (await listed.Json()).EnumerateArray().ToList();
        await Assert.That(entries).HasCount().EqualTo(1);
        await Assert.That(entries[0].String("id")).IsEqualTo(created.String("id"));

        await Assert.That(entries[0].Has("lastUsedAt")).IsFalse();
    }

    [Test]
    public async Task Registering_a_passkey_takes_more_than_a_bearer_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var nothing = await Passkeys.BeginRegistrationAsync(app, account.AccessToken, currentPassword: null);
        await Assert.That(nothing.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await nothing.Json()).Strings("errors")).IsNotEmpty();

        var wrong = await Passkeys.BeginRegistrationAsync(app, account.AccessToken, "not the password");
        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        // A body-less POST must be the same 400, not a 415 or 500.
        var empty = await app.Client.PostEmpty("/auth/passkeys/register/begin", account.AccessToken);
        await Assert.That(empty.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var listed = await (await app.Client.Get("/auth/passkeys", account.AccessToken)).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(0);
    }

    [Test]
    public async Task Wrong_passwords_at_registration_lock_the_account()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await Passkeys.BeginRegistrationAsync(app, account.AccessToken, "not the password");

        var right = await Passkeys.BeginRegistrationAsync(app, account.AccessToken, account.Password);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_fresh_second_factor_registers_a_passkey_without_a_password()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await account.EnrolAsync();

        var registered = await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, currentPassword: null);

        await Assert.That(registered.StatusCode).IsEqualTo(HttpStatusCode.Created);
    }

    [Test]
    public async Task A_passkey_registered_before_a_password_reset_cannot_sign_in_after_it()
    {
        var issued = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(issued)));

        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);
        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        await Assert.That((await app.Client.PostJson("/auth/password/forgot", new { email = account.Email })).StatusCode)
            .IsEqualTo(HttpStatusCode.NoContent);

        var reset = await app.Client.PostJson(
            "/auth/password/reset",
            new { token = issued[^1], newPassword = "a different correct horse" });

        await Assert.That(reset.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var afterwards = await Passkeys.SignInAsync(app, authenticator);

        await Assert.That(afterwards.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await afterwards.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task A_passkey_signs_in_with_no_password_and_no_identifier()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var signedIn = await Passkeys.SignInAsync(app, authenticator);
        await Assert.That(signedIn.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var body = await signedIn.Json();

        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(body.String("token_type")).IsEqualTo("Bearer");
    }

    [Test]
    public async Task A_verified_passkey_carries_hwk_user_and_mfa_and_names_itself_as_the_second_factor()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var body = await (await Passkeys.SignInAsync(app, authenticator)).Json();
        var claims = Account.DecodeClaims(body.String("access_token")!);

        await Assert.That(claims.Strings("amr")).IsEquivalentTo(new[] { "hwk", "user", "mfa" });
        await Assert.That(claims.String("toa_2fa_source")).IsEqualTo("passkey");
        await Assert.That(claims.Has("toa_2fa_at")).IsTrue();
    }

    [Test]
    public async Task Refreshing_a_passkey_session_keeps_the_methods_and_the_source()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var signedIn = await (await Passkeys.SignInAsync(app, authenticator)).Json();

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = signedIn.String("refresh_token") });
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var claims = Account.DecodeClaims((await refreshed.Json()).String("access_token")!);

        await Assert.That(claims.Strings("amr")).IsEquivalentTo(new[] { "hwk", "user", "mfa" });
        await Assert.That(claims.String("toa_2fa_source")).IsEqualTo("passkey");
        await Assert.That(claims.Has("toa_2fa_at")).IsTrue();
    }

    [Test]
    public async Task A_passkey_satisfies_RequiredForAll_without_a_totp_enrolment()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["TwoFactor:Enforcement"] = "RequiredForAll");

        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        // Proves the flag is set without the passkey, so its absence below is a difference, not a default.
        await Assert.That(account.Claims().String("toa_2fa_required")).IsEqualTo("true");

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var body = await (await Passkeys.SignInAsync(app, authenticator)).Json();
        var claims = Account.DecodeClaims(body.String("access_token")!);

        await Assert.That(claims.Has("toa_2fa_required")).IsFalse();
        await Assert.That(claims.Strings("amr")).Contains("mfa");
    }

    [Test]
    public async Task A_passkey_without_user_verification_claims_no_second_factor()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["Passkeys:RequireUserVerification"] = "false");

        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, userVerified: false);

        var body = await (await Passkeys.SignInAsync(app, authenticator, userVerified: false)).Json();
        var claims = Account.DecodeClaims(body.String("access_token")!);

        await Assert.That(claims.Strings("amr")).IsEquivalentTo(new[] { "hwk", "user" });
        await Assert.That(claims.Has("toa_2fa_source")).IsFalse();
    }

    /// <summary>
    /// An unverified assertion proves possession only, so a borrowed security key must not bypass the owner's second factor.
    /// </summary>
    [Test]
    public async Task An_unverified_passkey_challenges_an_enrolled_user_instead_of_signing_them_in()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["Passkeys:RequireUserVerification"] = "false");

        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, userVerified: false);
        await account.EnrolAsync();

        var challenged = await Passkeys.SignInAsync(app, authenticator, userVerified: false);
        await Assert.That(challenged.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var body = await challenged.Json();
        await Assert.That(body.Bool("two_factor_required")).IsTrue();
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(body.Has("refresh_token")).IsFalse();

        app.Time.AdvanceToNextTotpStep();

        var verified = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge = body.String("challenge"), code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verified.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var claims = Account.DecodeClaims((await verified.Json()).String("access_token")!);

        await Assert.That(claims.Strings("amr")).IsEquivalentTo(new[] { "hwk", "user", "otp", "mfa" });
        await Assert.That(claims.String("toa_2fa_source")).IsEqualTo("otp");
    }

    [Test]
    public async Task Malformed_authenticator_data_is_refused_rather_than_escaping()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertion = Passkeys.Fields(authenticator.Get(begin, TestApp.Origin));

        // 32 bytes of RP id hash, flags UP|UV|ED, a counter, and no CBOR where the extension map must be.
        var malformed = new byte[37];
        malformed[32] = 0x85;
        assertion["authenticatorData"] = SoftwareAuthenticator.Encode(malformed);

        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task An_unverified_assertion_is_refused_when_user_verification_is_required()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var response = await Passkeys.SignInAsync(app, authenticator, userVerified: false);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task A_tampered_signature_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertion = Passkeys.Fields(authenticator.Get(begin, TestApp.Origin));

        using var impostor = new SoftwareAuthenticator();
        assertion["signature"] = Passkeys.Fields(impostor.Get(begin, TestApp.Origin))["signature"];

        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_sign_count_that_does_not_advance_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);
        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        // What a cloned credential reports, unaware of the original's use.
        authenticator.SignCount = 0;

        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Two separate assertions with advancing counters, not a byte replay, so clone detection cannot be what refuses the second.
    /// </summary>
    [Test]
    public async Task A_challenge_cannot_be_spent_twice()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var first = authenticator.Get(begin, TestApp.Origin);
        var second = authenticator.Get(begin, TestApp.Origin);

        await Assert.That((await app.Client.PostJson("/auth/passkeys/assertion/complete", first)).StatusCode)
            .IsEqualTo(HttpStatusCode.OK);

        await Assert.That((await app.Client.PostJson("/auth/passkeys/assertion/complete", second)).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_challenge_raced_by_several_assertions_signs_in_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertions = Enumerable.Range(0, 8).Select(_ => authenticator.Get(begin, TestApp.Origin)).ToList();

        var responses = await Task.WhenAll(assertions.Select(assertion =>
            app.Client.PostJson("/auth/passkeys/assertion/complete", assertion)));

        await Assert.That(responses.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
    }

    [Test]
    public async Task An_assertion_from_another_origin_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertion = authenticator.Get(begin, "https://phishing.example");

        await Assert.That((await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion)).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task An_assertion_naming_the_wrong_account_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var owner = await Account.RegisterAsync(app, "ada");
        var other = await Account.RegisterAsync(app, "grace");
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, owner.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertion = Passkeys.Fields(authenticator.Get(begin, TestApp.Origin));

        var grace = await (await app.Client.Get("/test/me", other.AccessToken)).Json();
        assertion["userHandle"] = SoftwareAuthenticator.Encode(Guid.Parse(grace.String("id")!).ToByteArray());

        await Assert.That((await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion)).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_credential_nobody_registered_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        using var stranger = new SoftwareAuthenticator();

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();

        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", stranger.Get(begin, TestApp.Origin));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task Deleting_a_passkey_without_proof_is_refused_as_a_removal()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var id = (await (await Passkeys.RegisterAsync(app, account.AccessToken, authenticator)).Json()).String("id")!;

        var refused = await app.Client.Delete($"/auth/passkeys/{id}", new { }, account.AccessToken);
        var errors = string.Join(" ", (await refused.Json()).Strings("errors"));

        await Assert.That(refused.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(errors).Contains("Removing a passkey");
        await Assert.That(errors).DoesNotContain("egister");
    }

    [Test]
    public async Task Deleting_a_passkey_takes_it_out_of_the_list_and_out_of_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var created = await (await Passkeys.RegisterAsync(app, account.AccessToken, authenticator)).Json();
        var id = created.String("id")!;

        await Assert.That((await app.Client.Delete($"/auth/passkeys/{id}", new { currentPassword = account.Password }, account.AccessToken)).StatusCode)
            .IsEqualTo(HttpStatusCode.NoContent);

        // Deleting ends every session including this one, so the list is read from a new one.
        var signedIn = await (await account.LoginAsync()).Json();
        var listed = await (await app.Client.Get("/auth/passkeys", signedIn.String("access_token"))).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(0);

        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Deleting_a_passkey_takes_more_than_a_bearer_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var id = (await (await Passkeys.RegisterAsync(app, account.AccessToken, authenticator)).Json()).String("id")!;

        var bare = await app.Client.Delete($"/auth/passkeys/{id}", account.AccessToken);
        var wrong = await app.Client.Delete($"/auth/passkeys/{id}", new { currentPassword = "not the password" }, account.AccessToken);

        await Assert.That(bare.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var listed = await (await app.Client.Get("/auth/passkeys", account.AccessToken)).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(1);
    }

    /// <summary>
    /// Nothing records which session a passkey opened, so every session must end or that one outlives the key.
    /// </summary>
    [Test]
    public async Task Deleting_a_passkey_ends_the_sessions_on_the_account()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var id = (await (await Passkeys.RegisterAsync(app, account.AccessToken, authenticator)).Json()).String("id")!;
        var opened = await (await Passkeys.SignInAsync(app, authenticator)).Json();

        await app.Client.Delete($"/auth/passkeys/{id}", new { currentPassword = account.Password }, account.AccessToken);

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = opened.String("refresh_token") });
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        await Assert.That((await app.Client.Get("/auth/passkeys", opened.String("access_token"))).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);

        var fresh = await (await account.LoginAsync()).Json();
        var sessions = await (await app.Client.Get("/auth/sessions", fresh.String("access_token"))).Json();
        await Assert.That(sessions.EnumerateArray().ToList()).HasCount().EqualTo(1);
    }

    [Test]
    public async Task Deleting_someone_elses_passkey_answers_404()
    {
        await using var app = await TestApp.StartAsync();
        var owner = await Account.RegisterAsync(app, "ada");
        var other = await Account.RegisterAsync(app, "grace");
        using var authenticator = new SoftwareAuthenticator();

        var created = await (await Passkeys.RegisterAsync(app, owner.AccessToken, authenticator)).Json();

        var response = await app.Client.Delete($"/auth/passkeys/{created.String("id")}", new { currentPassword = other.Password }, other.AccessToken);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);

        var listed = await (await app.Client.Get("/auth/passkeys", owner.AccessToken)).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(1);
    }

    [Test]
    public async Task The_registration_endpoints_refuse_an_anonymous_caller()
    {
        await using var app = await TestApp.StartAsync();

        await Assert.That((await app.Client.PostJson("/auth/passkeys/register/begin", new { })).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);

        await Assert.That((await app.Client.Get("/auth/passkeys")).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Beginning_an_assertion_says_nothing_about_who_is_registered()
    {
        await using var app = await TestApp.StartAsync();

        var empty = await app.Client.PostJson("/auth/passkeys/assertion/begin", new { });
        await Assert.That(empty.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var body = await empty.Json();
        await Assert.That(body.String("challenge")).IsNotNull();
        await Assert.That(body.Has("options")).IsTrue();

        var options = body.GetProperty("options");
        await Assert.That(options.String("rpId")).IsEqualTo("localhost");
        await Assert.That(options.String("userVerification")).IsEqualTo("required");

        var allowed = options.TryGetProperty("allowCredentials", out var list) ? list.GetArrayLength() : 0;
        await Assert.That(allowed).IsEqualTo(0);
    }

    /// <summary>Confirming a two-factor enrolment moves the security stamp, which makes the earlier token stale.</summary>
    [Test]
    public async Task A_token_from_before_a_credential_change_cannot_list_passkeys()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await account.EnrolAsync();

        var response = await app.Client.Get("/auth/passkeys", stale);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_token");
    }

    [Test]
    public async Task A_passkey_sign_in_shows_up_as_a_session()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var body = await (await Passkeys.SignInAsync(app, authenticator)).Json();
        var sessions = await (await app.Client.Get("/auth/sessions", body.String("access_token")!)).Json();

        var current = sessions.EnumerateArray().Single(session => session.Bool("isCurrent") == true);
        await Assert.That(current.Strings("authenticationMethods")).IsEquivalentTo(new[] { "hwk", "user", "mfa" });
    }
}

/// <summary>Drives the passkey endpoints the way a client does. Everything goes over HTTP.</summary>
internal static class Passkeys
{
    public static Task<HttpResponseMessage> BeginRegistrationAsync(
        TestApp app,
        string accessToken,
        string? currentPassword = Account.DefaultPassword) =>
        app.Client.PostJson("/auth/passkeys/register/begin", new { currentPassword }, accessToken);

    public static async Task<HttpResponseMessage> RegisterAsync(
        TestApp app,
        string accessToken,
        SoftwareAuthenticator authenticator,
        string? label = null,
        bool userVerified = true,
        string? currentPassword = Account.DefaultPassword)
    {
        var begin = await BeginRegistrationAsync(app, accessToken, currentPassword);

        if (begin.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Register begin failed: {begin.StatusCode} {await begin.Content.ReadAsStringAsync()}");

        var created = Fields(authenticator.Create(await begin.Json(), TestApp.Origin, userVerified));

        if (label is not null)
            created["label"] = label;

        return await app.Client.PostJson("/auth/passkeys/register/complete", created, accessToken);
    }

    public static async Task<HttpResponseMessage> SignInAsync(
        TestApp app,
        SoftwareAuthenticator authenticator,
        bool userVerified = true)
    {
        var begin = await app.Client.PostJson("/auth/passkeys/assertion/begin", new { });

        if (begin.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Assertion begin failed: {begin.StatusCode} {await begin.Content.ReadAsStringAsync()}");

        return await app.Client.PostJson(
            "/auth/passkeys/assertion/complete",
            authenticator.Get(await begin.Json(), TestApp.Origin, userVerified));
    }

    public static Dictionary<string, object?> Fields(object response) =>
        JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(response))!;
}
