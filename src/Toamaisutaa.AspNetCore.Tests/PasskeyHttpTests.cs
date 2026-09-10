using System.Net;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The two WebAuthn ceremonies over the real pipeline, driven by a software authenticator that
/// builds its own attestation and signs its own assertions.
/// </summary>
/// <remarks>
/// Every assertion here reads raw JSON rather than deserialising through the package's own records,
/// for the reason the rest of this suite does: a test that takes its expectation from the type under
/// test agrees with it even when a field has gone missing on the wire.
/// </remarks>
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

        var created = await registered.Json();
        await Assert.That(created.String("label")).IsEqualTo("work laptop");
        await Assert.That(created.String("id")).IsNotNull();
        await Assert.That(created.Strings("transports")).IsEquivalentTo(new[] { "internal" });

        var listed = await app.Client.Get("/auth/passkeys", account.AccessToken);
        await Assert.That(listed.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var entries = (await listed.Json()).EnumerateArray().ToList();
        await Assert.That(entries).HasCount().EqualTo(1);
        await Assert.That(entries[0].String("id")).IsEqualTo(created.String("id"));

        // Never signed anything yet, and a list is read to decide what to delete.
        await Assert.That(entries[0].Has("lastUsedAt")).IsFalse();
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

        // The same field names /auth/login returns. A passkey sign-in that answered a different
        // shape would make a client carry two parsers for one concept.
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

    /// <summary>
    /// The rule this repository has been bitten by three times: a claim is not done until the
    /// refresh path answers for it. A passkey session that refreshed into a password-only one would
    /// fail its policy exactly one access-token lifetime after a perfectly good sign-in.
    /// </summary>
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

    /// <summary>
    /// The whole point of the feature under <c>RequiredForAll</c>: one prompt proved possession and
    /// verified the person, so nothing should be telling them to go and enrol a TOTP authenticator
    /// as well.
    /// </summary>
    [Test]
    public async Task A_passkey_satisfies_RequiredForAll_without_a_totp_enrolment()
    {
        await using var app = await TestApp.StartAsync(
            configure: settings => settings["TwoFactor:Enforcement"] = "RequiredForAll");

        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        // The password sign-in this account came from is told to enrol, which is what makes the
        // passkey token below a difference rather than a default.
        await Assert.That(account.Claims().String("toa_2fa_required")).IsEqualTo("true");

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var body = await (await Passkeys.SignInAsync(app, authenticator)).Json();
        var claims = Account.DecodeClaims(body.String("access_token")!);

        await Assert.That(claims.Has("toa_2fa_required")).IsFalse();
        await Assert.That(claims.Strings("amr")).Contains("mfa");
    }

    /// <summary>
    /// A passkey the authenticator did not verify the user for is one factor, not two - so it signs
    /// in, and it does not claim the second factor it did not perform.
    /// </summary>
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
    /// With user verification required, an authenticator that only checked for a touch has to be
    /// refused. Configuration says two factors and the ceremony delivered one.
    /// </summary>
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

        // A different key's signature over the same data. Everything else about the assertion is
        // exactly what a real authenticator would have produced.
        using var impostor = new SoftwareAuthenticator();
        assertion["signature"] = Passkeys.Fields(impostor.Get(begin, TestApp.Origin))["signature"];

        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// The counter is the only thing that catches a cloned authenticator, and it only catches one if
    /// a value that fails to advance is refused.
    /// </summary>
    [Test]
    public async Task A_sign_count_that_does_not_advance_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);
        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        // Back to what it was before that sign-in, which is what a copy of the credential would
        // report: the copy has no idea how often the original has been used.
        authenticator.SignCount = 0;

        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Two assertions over one challenge, the second with a higher counter and a valid signature -
    /// so nothing but the challenge having been spent can refuse it.
    /// </summary>
    /// <remarks>
    /// Replaying the identical bytes would not test this. The counter has moved on by then, so that
    /// version passed with the consumed check deleted: the clone detection was refusing it and the
    /// test was named after something it did not touch.
    /// </remarks>
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

    /// <summary>
    /// The relying party id is what stops a phishing site using a credential, and the origin is what
    /// the server checks it against. A ceremony claiming to have happened somewhere else is the
    /// exact shape of that attack.
    /// </summary>
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

    /// <summary>
    /// Sign-in begins with no identifier, so the user handle the authenticator returns is the only
    /// thing that says which account is arriving. One that names a different account than the
    /// credential belongs to has to be refused, or the handle is decoration.
    /// </summary>
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

        // Ada's credential, ada's signature, and grace's user handle bolted on.
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

        // Never registered anywhere. It signs correctly and belongs to no account, which has to be
        // the same answer as a wrong signature.
        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", stranger.Get(begin, TestApp.Origin));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task Deleting_a_passkey_takes_it_out_of_the_list_and_out_of_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        var created = await (await Passkeys.RegisterAsync(app, account.AccessToken, authenticator)).Json();
        var id = created.String("id")!;

        await Assert.That((await app.Client.Delete($"/auth/passkeys/{id}", account.AccessToken)).StatusCode)
            .IsEqualTo(HttpStatusCode.NoContent);

        var listed = await (await app.Client.Get("/auth/passkeys", account.AccessToken)).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(0);

        await Assert.That((await Passkeys.SignInAsync(app, authenticator)).StatusCode)
            .IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// 404 covers a passkey that does not exist and one belonging to somebody else alike, or the
    /// endpoint becomes a way to find out which credential ids are real.
    /// </summary>
    [Test]
    public async Task Deleting_someone_elses_passkey_answers_404()
    {
        await using var app = await TestApp.StartAsync();
        var owner = await Account.RegisterAsync(app, "ada");
        var other = await Account.RegisterAsync(app, "grace");
        using var authenticator = new SoftwareAuthenticator();

        var created = await (await Passkeys.RegisterAsync(app, owner.AccessToken, authenticator)).Json();

        var response = await app.Client.Delete($"/auth/passkeys/{created.String("id")}", other.AccessToken);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);

        // And it is still there for the person who owns it.
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

    /// <summary>
    /// Sign-in begins with no identifier and no account picker of ours, so the begin endpoint has to
    /// answer identically whether or not anybody is registered. Anything else is an enumeration
    /// oracle on an anonymous endpoint.
    /// </summary>
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

        // No credential list, so the response is byte-for-byte the same shape whether or not the
        // account somebody guessed at exists.
        var allowed = options.TryGetProperty("allowCredentials", out var list) ? list.GetArrayLength() : 0;
        await Assert.That(allowed).IsEqualTo(0);
    }

    /// <summary>
    /// A stale token has to be refused rather than escaping as a 500, the same as everywhere else
    /// that resolves the caller. Confirming a two-factor enrolment moves the stamp, which is the
    /// ordinary way to be holding one.
    /// </summary>
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
    public static async Task<HttpResponseMessage> RegisterAsync(
        TestApp app,
        string accessToken,
        SoftwareAuthenticator authenticator,
        string? label = null,
        bool userVerified = true)
    {
        var begin = await app.Client.PostEmpty("/auth/passkeys/register/begin", accessToken);

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

    /// <summary>
    /// The authenticator's output as a mutable bag, so a test can substitute one field and leave the
    /// rest exactly as a real authenticator produced it.
    /// </summary>
    public static Dictionary<string, object?> Fields(object response) =>
        JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(response))!;
}
