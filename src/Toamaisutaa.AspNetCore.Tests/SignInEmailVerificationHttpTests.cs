using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

public class SignInEmailVerificationHttpTests
{
    private const string Password = Account.DefaultPassword;

    private static Task<TestApp> StartAsync(Action<Dictionary<string, string?>>? configure = null, Action<IServiceCollection>? configureServices = null) =>
        TestApp.StartAsync(
            configure: settings =>
            {
                settings["LocalLogin:RequireVerifiedEmailForSignIn"] = "true";
                configure?.Invoke(settings);
            },
            configureServices: configureServices);

    private static Task<HttpResponseMessage> RegisterAsync(TestApp app, string userName = "ada", string? email = null) =>
        app.Client.PostJson("/auth/register", new { userName, email = email ?? $"{userName}@example.com", password = Password });

    private static Task<HttpResponseMessage> LoginAsync(TestApp app, string identifier = "ada", string password = Password) =>
        app.Client.PostJson("/auth/login", new { identifier, password });

    private static Task<HttpResponseMessage> VerifyAsync(TestApp app, string challenge, string code) =>
        app.Client.PostJson("/auth/email/verify-code", new { challenge, code });

    private static async Task<string> ChallengeOf(HttpResponseMessage response) => (await response.Json()).String("challenge")!;

    /// <summary>The right code with its last digit moved on, so it is never accidentally right.</summary>
    private static string Wrong(string code) => code[..5] + (char)('0' + ((code[5] - '0' + 1) % 10));

    private static async Task SetUnverifiedAsync(TestApp app, string userName)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();

        var updated = await db.PasswordCredentials
            .Where(credential => credential.NormalizedUserName == userName.ToUpperInvariant())
            .ExecuteUpdateAsync(setters => setters.SetProperty(credential => credential.EmailConfirmedAt, (DateTimeOffset?)null));

        if (updated != 1)
            throw new InvalidOperationException($"Expected to unverify one credential, unverified {updated}.");
    }

    /// <summary>Registers and confirms, handing back the finished sign-in.</summary>
    private static async Task<JsonElement> RegisterVerifiedAsync(TestApp app, string userName = "ada")
    {
        var challenge = await ChallengeOf(await RegisterAsync(app, userName));
        var verify = await VerifyAsync(app, challenge, app.IssuedEmailCodes[^1].Code);

        if (verify.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Verification failed: {verify.StatusCode} {await verify.Content.ReadAsStringAsync()}");

        return await verify.Json();
    }

    [Test]
    public async Task Registering_answers_201_with_a_challenge_instead_of_tokens_and_mails_a_code()
    {
        await using var app = await StartAsync();

        var response = await RegisterAsync(app);
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That(body.Bool("email_verification_required")).IsEqualTo(true);
        await Assert.That(body.String("challenge")).IsNotNull();
        await Assert.That(body.String("method")).IsEqualTo("code");
        await Assert.That(body.String("email")).IsEqualTo("a***@example.com");
        await Assert.That(body.TryGetProperty("expires_in", out var expiresIn) && expiresIn.GetInt32() == 3600).IsTrue();
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(body.Has("refresh_token")).IsFalse();

        var sent = app.IssuedEmailCodes.Single();
        await Assert.That(sent.Email).IsEqualTo("ada@example.com");
        await Assert.That(sent.Code.Length == 6 && sent.Code.All(char.IsAsciiDigit)).IsTrue();
    }

    [Test]
    public async Task A_wrong_code_answers_400_invalid_code_and_the_right_one_signs_in()
    {
        await using var app = await StartAsync();
        var challenge = await ChallengeOf(await RegisterAsync(app));
        var code = app.IssuedEmailCodes.Single().Code;

        var wrong = await VerifyAsync(app, challenge, Wrong(code));
        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await wrong.Json()).String("error")).IsEqualTo("invalid_code");

        var right = await VerifyAsync(app, challenge, code);
        var body = await right.Json();
        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("email")).IsEqualTo("ada@example.com");

        // Confirmed for good: the next sign-in is an ordinary one, and the challenge is spent.
        var login = await LoginAsync(app);
        await Assert.That((await login.Json()).String("access_token")).IsNotNull();
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(1);

        var again = await VerifyAsync(app, challenge, code);
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_code_past_its_lifetime_answers_code_expired()
    {
        await using var app = await StartAsync();
        var challenge = await ChallengeOf(await RegisterAsync(app));

        app.Time.Advance(TimeSpan.FromMinutes(16));

        var response = await VerifyAsync(app, challenge, app.IssuedEmailCodes.Single().Code);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("code_expired");
    }

    [Test]
    public async Task The_fifth_wrong_code_spends_it_so_even_the_right_one_then_answers_code_expired()
    {
        // Lockout raised out of the way, so this is the code's own limit and not the account's.
        await using var app = await StartAsync(settings => settings["LocalLogin:MaxFailedAttempts"] = "50");
        var challenge = await ChallengeOf(await RegisterAsync(app));
        var code = app.IssuedEmailCodes.Single().Code;

        for (var attempt = 1; attempt <= 4; attempt++)
            await Assert.That((await (await VerifyAsync(app, challenge, Wrong(code))).Json()).String("error")).IsEqualTo("invalid_code");

        var fifth = await VerifyAsync(app, challenge, Wrong(code));
        await Assert.That((await fifth.Json()).String("error")).IsEqualTo("code_expired");

        var right = await VerifyAsync(app, challenge, code);
        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await right.Json()).String("error")).IsEqualTo("code_expired");
    }

    [Test]
    public async Task Wrong_codes_count_toward_the_account_lockout()
    {
        await using var app = await StartAsync();
        var challenge = await ChallengeOf(await RegisterAsync(app));
        var code = app.IssuedEmailCodes.Single().Code;

        for (var attempt = 1; attempt <= 5; attempt++)
            await VerifyAsync(app, challenge, Wrong(code));

        var login = await LoginAsync(app);
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Asking_again_inside_the_cooldown_answers_429_and_after_it_sends_a_new_code()
    {
        await using var app = await StartAsync(settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00");
        var challenge = await ChallengeOf(await RegisterAsync(app));
        var first = app.IssuedEmailCodes.Single().Code;

        var tooSoon = await app.Client.PostJson("/auth/email/resend-code", new { challenge });
        await Assert.That(tooSoon.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(tooSoon.Headers.RetryAfter).IsNotNull();
        await Assert.That((await tooSoon.Json()).Strings("errors")).IsNotEmpty();
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(1);

        app.Time.Advance(TimeSpan.FromSeconds(61));

        var resend = await app.Client.PostJson("/auth/email/resend-code", new { challenge });
        await Assert.That(resend.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(2);

        var second = app.IssuedEmailCodes[^1].Code;

        // Asking again retires the first, unless the two happen to be the same six digits.
        if (first != second)
            await Assert.That((await (await VerifyAsync(app, challenge, first)).Json()).String("error")).IsEqualTo("invalid_code");

        await Assert.That((await VerifyAsync(app, challenge, second)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Resending_with_an_unknown_challenge_answers_401()
    {
        await using var app = await StartAsync();

        var response = await app.Client.PostJson("/auth/email/resend-code", new { challenge = "not-a-challenge" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task The_right_password_for_an_unverified_account_answers_a_challenge_and_mails_a_new_code()
    {
        await using var app = await StartAsync();
        await RegisterAsync(app);

        var login = await LoginAsync(app);
        var body = await login.Json();

        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.Bool("email_verification_required")).IsEqualTo(true);
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(2);

        var verify = await VerifyAsync(app, body.String("challenge")!, app.IssuedEmailCodes[^1].Code);
        await Assert.That((await verify.Json()).String("access_token")).IsNotNull();
    }

    [Test]
    public async Task Signing_in_again_inside_the_cooldown_still_answers_a_challenge_the_first_code_answers()
    {
        await using var app = await StartAsync(settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00");
        await RegisterAsync(app);

        var login = await LoginAsync(app);

        await Assert.That((await login.Json()).Bool("email_verification_required")).IsEqualTo(true);
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(1);

        var verify = await VerifyAsync(app, await ChallengeOf(login), app.IssuedEmailCodes.Single().Code);
        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>Whether an address is verified is nobody's business without the password.</summary>
    [Test]
    public async Task A_wrong_password_answers_the_plain_refusal_and_sends_nothing()
    {
        await using var app = await StartAsync();
        await RegisterAsync(app);

        var wrong = await LoginAsync(app, password: "not the password");
        var unknown = await LoginAsync(app, identifier: "nobody");

        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(await wrong.Content.ReadAsStringAsync()).IsEqualTo(await unknown.Content.ReadAsStringAsync());
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(1);
    }

    [Test]
    public async Task Registering_a_taken_name_or_address_answers_409_as_it_does_with_the_option_off()
    {
        await using var app = await StartAsync();
        await RegisterAsync(app);

        var name = await RegisterAsync(app, "ada", "other@example.com");
        var address = await RegisterAsync(app, "grace", "ada@example.com");

        await Assert.That(name.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        await Assert.That(address.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        await Assert.That(app.IssuedEmailCodes.Count).IsEqualTo(1);
    }

    [Test]
    public async Task Registering_without_an_address_answers_400()
    {
        await using var app = await StartAsync();

        var response = await app.Client.PostJson("/auth/register", new { userName = "ada", password = Password });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(app.IssuedEmailCodes).IsEmpty();
    }

    [Test]
    public async Task With_the_option_off_registration_signs_straight_in_and_mails_no_code()
    {
        await using var app = await TestApp.StartAsync();

        var register = await RegisterAsync(app);
        await Assert.That(register.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That((await register.Json()).String("access_token")).IsNotNull();

        var login = await LoginAsync(app);
        await Assert.That((await login.Json()).String("access_token")).IsNotNull();
        await Assert.That(app.IssuedEmailCodes).IsEmpty();

        // Unmapped, so the fallback policy answers before any route would.
        var verify = await VerifyAsync(app, "anything", "123456");
        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(await verify.Content.ReadAsStringAsync()).DoesNotContain("invalid_grant");
    }

    [Test]
    public async Task An_account_with_a_second_factor_is_sent_on_to_it_once_the_address_is_confirmed()
    {
        await using var app = await StartAsync();
        var signedIn = await RegisterVerifiedAsync(app);

        var account = Account.SignedIn(app, "ada", signedIn.String("access_token")!);
        await account.EnrolForRecoveryCodesAsync();

        await SetUnverifiedAsync(app, "ada");

        var login = await LoginAsync(app);
        await Assert.That((await login.Json()).Bool("email_verification_required")).IsEqualTo(true);

        var verify = await VerifyAsync(app, await ChallengeOf(login), app.IssuedEmailCodes[^1].Code);
        var body = await verify.Json();

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.Bool("two_factor_required")).IsEqualTo(true);
        await Assert.That(body.Has("access_token")).IsFalse();

        app.Time.AdvanceToNextTotpStep();

        var second = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge = body.String("challenge"), code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That((await second.Json()).String("access_token")).IsNotNull();

        // Confirmed on the way, so the next sign-in goes straight to the second factor.
        var next = await LoginAsync(app);
        await Assert.That((await next.Json()).Bool("two_factor_required")).IsEqualTo(true);
    }

    [Test]
    public async Task A_password_session_of_an_unverified_account_stops_refreshing()
    {
        await using var app = await StartAsync();
        var ada = await RegisterVerifiedAsync(app, "ada");
        var grace = await RegisterVerifiedAsync(app, "grace");

        await SetUnverifiedAsync(app, "ada");

        var refused = await app.Client.PostJson("/auth/refresh", new { refreshToken = ada.String("refresh_token") });
        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = grace.String("refresh_token") });

        await Assert.That(refused.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task A_redeemed_verification_link_satisfies_the_requirement_too()
    {
        await using var app = await StartAsync();
        var signedIn = await RegisterVerifiedAsync(app);
        await SetUnverifiedAsync(app, "ada");

        var request = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "ada@example.com", currentPassword = Password },
            signedIn.String("access_token")!);

        await Assert.That(request.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var redeem = await app.Client.PostJson("/auth/email/verify", new { token = app.IssuedEmailVerifications[^1].Token });
        await Assert.That(redeem.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var login = await LoginAsync(app);
        await Assert.That((await login.Json()).String("access_token")).IsNotNull();
    }

    [Test]
    public async Task A_challenge_stops_working_once_the_password_changes()
    {
        await using var app = await StartAsync();
        var signedIn = await RegisterVerifiedAsync(app);
        await SetUnverifiedAsync(app, "ada");

        var challenge = await ChallengeOf(await LoginAsync(app));
        var code = app.IssuedEmailCodes[^1].Code;

        var change = await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = Password, newPassword = "a different passphrase entirely" },
            signedIn.String("access_token")!);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var verify = await VerifyAsync(app, challenge, code);
        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_method_registered_in_its_place_is_the_one_used()
    {
        var method = new PassphraseMethod();

        await using var app = await StartAsync(configureServices: services => services.AddSingleton<IEmailVerificationMethod>(method));

        var register = await RegisterAsync(app);
        var body = await register.Json();

        await Assert.That(body.String("method")).IsEqualTo("passphrase");
        await Assert.That(method.Issued).IsEqualTo(1);
        await Assert.That(app.IssuedEmailCodes).IsEmpty();

        var wrong = await VerifyAsync(app, body.String("challenge")!, "open barley");
        await Assert.That((await wrong.Json()).String("error")).IsEqualTo("invalid_code");

        var right = await VerifyAsync(app, body.String("challenge")!, PassphraseMethod.Passphrase);
        await Assert.That((await right.Json()).String("access_token")).IsNotNull();
    }

    [Test]
    public async Task Startup_refuses_the_option_with_no_notifier_to_mail_the_code()
    {
        var started = async () =>
        {
            await using var app = await TestApp.StartAsync(
                includeEmailVerificationNotifier: false,
                configure: settings => settings["LocalLogin:RequireVerifiedEmailForSignIn"] = "true");
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("RequireVerifiedEmailForSignIn");
    }

    [Test]
    public async Task Startup_refuses_the_option_with_a_notifier_that_cannot_send_a_code()
    {
        var started = async () =>
        {
            await using var app = await TestApp.StartAsync(
                includeEmailVerificationNotifier: false,
                includeMagicLinkNotifier: false,
                configure: settings => settings["LocalLogin:RequireVerifiedEmailForSignIn"] = "true",
                configureServices: services => services.AddSingleton<IEmailVerificationNotifier, LinkOnlyNotifier>());
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains(nameof(LinkOnlyNotifier));
    }

    private sealed class LinkOnlyNotifier : IEmailVerificationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class PassphraseMethod : IEmailVerificationMethod
    {
        public const string Passphrase = "open sesame";

        public int Issued { get; private set; }

        public string Name => "passphrase";

        public Task<EmailVerificationIssueResult> IssueAsync(EmailVerificationIssueRequest request, CancellationToken cancellationToken = default)
        {
            Issued++;
            return Task.FromResult(EmailVerificationIssueResult.Sent);
        }

        public Task<EmailVerificationProofOutcome> VerifyAsync(EmailVerificationProofRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(request.Proof == Passphrase ? EmailVerificationProofOutcome.Verified : EmailVerificationProofOutcome.Invalid);
    }
}
