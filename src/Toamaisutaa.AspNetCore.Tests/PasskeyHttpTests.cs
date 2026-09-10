using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

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

        // No Location. The one this used to send was relative, began with the user id and resolved
        // to a path nothing maps, so a client following it as RFC 9110 allows got a 404.
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

        // Never signed anything yet, and a list is read to decide what to delete.
        await Assert.That(entries[0].Has("lastUsedAt")).IsFalse();
    }

    /// <summary>
    /// A passkey signs in on its own, so registering one adds a way into the account. A bearer token
    /// is not proof of anything but a bearer token: the one lifted from a log line or a compromised
    /// browser is exactly what the account holder is about to revoke every session over.
    /// </summary>
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

        // A body-less POST is the same refusal rather than a 415 or a 500: the proof is missing
        // either way, and an endpoint that fell over on it would be a new hole in place of the old.
        var empty = await app.Client.PostEmpty("/auth/passkeys/register/begin", account.AccessToken);
        await Assert.That(empty.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var listed = await (await app.Client.Get("/auth/passkeys", account.AccessToken)).Json();
        await Assert.That(listed.EnumerateArray().ToList()).HasCount().EqualTo(0);
    }

    /// <summary>
    /// The other proof, and the one an account with no password has: a second factor presented
    /// within <c>Passkeys:RegistrationProofWindow</c>. It is the <c>toa_2fa_at</c> claim
    /// <c>RequireFreshSecondFactor</c> reads, so a step-up satisfies this too.
    /// </summary>
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

    /// <summary>
    /// A reset is what somebody does when they think another person has been in their account, and
    /// it ends every session, every reset link and every trusted device. A passkey registered before
    /// it is a credential that signs in with no password at all, so leaving one standing would mean
    /// the one remediation the package offers remediated nothing.
    /// </summary>
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
    /// Enrolment alone decides a challenge - <c>TwoFactorGate</c> says so in its own summary, and
    /// the password and magic-link paths both honour it. An assertion the authenticator did not
    /// verify the user for proved possession and nothing else, so a borrowed security key must not
    /// beat the second factor its owner turned on.
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

        // The same second shape /auth/login answers with, so a client has one branch rather than two.
        var body = await challenged.Json();
        await Assert.That(body.Bool("two_factor_required")).IsTrue();
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(body.Has("refresh_token")).IsFalse();

        app.Time.AdvanceToNextTotpStep();

        var verified = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge = body.String("challenge"), code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verified.StatusCode).IsEqualTo(HttpStatusCode.OK);

        // What the passkey proved, replayed off the challenge, plus what the code proved.
        var claims = Account.DecodeClaims((await verified.Json()).String("access_token")!);

        await Assert.That(claims.Strings("amr")).IsEquivalentTo(new[] { "hwk", "user", "otp", "mfa" });
        await Assert.That(claims.String("toa_2fa_source")).IsEqualTo("otp");
    }

    /// <summary>
    /// Authenticator data that is valid base64url and nonsense inside has to be a 401 like every
    /// other refusal here. The flags byte below sets the extension-data bit with no CBOR after it,
    /// which is the shape that escaped as an unhandled exception from an anonymous endpoint.
    /// </summary>
    [Test]
    public async Task Malformed_authenticator_data_is_refused_rather_than_escaping()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();

        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var begin = await (await app.Client.PostJson("/auth/passkeys/assertion/begin", new { })).Json();
        var assertion = Passkeys.Fields(authenticator.Get(begin, TestApp.Origin));

        // 32 bytes of relying-party hash, then UP|UV|ED, then a counter, and nothing where the
        // extension map has to be.
        var malformed = new byte[37];
        malformed[32] = 0x85;
        assertion["authenticatorData"] = SoftwareAuthenticator.Encode(malformed);

        var response = await app.Client.PostJson("/auth/passkeys/assertion/complete", assertion);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
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

/// <summary>Hands back the reset token, which is otherwise only ever seen by the notifier.</summary>
internal sealed class CapturingResetNotifier(List<string> issued) : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        issued.Add(resetToken);
        return Task.CompletedTask;
    }
}

/// <summary>Drives the passkey endpoints the way a client does. Everything goes over HTTP.</summary>
internal static class Passkeys
{
    /// <summary>
    /// Starts a registration. <paramref name="currentPassword"/> is the proof the endpoint asks for,
    /// and null is a caller presenting nothing but their bearer token.
    /// </summary>
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

    /// <summary>
    /// The authenticator's output as a mutable bag, so a test can substitute one field and leave the
    /// rest exactly as a real authenticator produced it.
    /// </summary>
    public static Dictionary<string, object?> Fields(object response) =>
        JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(response))!;
}
