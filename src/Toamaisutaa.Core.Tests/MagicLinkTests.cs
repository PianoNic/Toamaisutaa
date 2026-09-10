using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The emailed sign-in link. Two rules carry the whole feature: it only ever goes to an address
/// somebody has proven, and it says <c>email</c> in <c>amr</c> rather than <c>pwd</c>, because no
/// password was typed.
/// </summary>
public class MagicLinkTests
{
    // ── Asking for one ──

    [Test]
    public async Task AVerifiedAddressGetsALink()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        var outcome = await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.Sent);
        await Assert.That(harness.MagicLinkNotifier.Sent.Single().UserId).IsEqualTo(user.Id);
    }

    [Test]
    public async Task TheStoredTokenIsAHashOfWhatWasSent()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        var raw = harness.MagicLinkNotifier.Sent.Single().Token;
        await Assert.That(harness.Passwords.MagicLinkTokens.Single().TokenHash).IsNotEqualTo(raw);
    }

    // The rule the whole feature rests on: this link is a session, so it may not be sent to an
    // address that could be a typo or could since have changed hands.
    [Test]
    public async Task AnUnverifiedAddressGetsNothing()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var outcome = await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.EmailNotVerified);
        await Assert.That(harness.MagicLinkNotifier.Sent).IsEmpty();
        await Assert.That(harness.Passwords.MagicLinkTokens).IsEmpty();
    }

    [Test]
    public async Task AnUnknownAddressGetsNothing()
    {
        var harness = PasswordHarness.Create();

        var outcome = await harness.Accounts.RequestMagicLinkAsync("nobody@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.UnknownEmail);
        await Assert.That(harness.MagicLinkNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task AnAccountAnIdentityProviderOwnsGetsNothing()
    {
        var harness = PasswordHarness.Create();
        harness.ProvisionExternalUser("sso@example.com");

        var outcome = await harness.Accounts.RequestMagicLinkAsync("sso@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.NoLocalCredential);
        await Assert.That(harness.MagicLinkNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task ANotifierThatThrowsIsReportedRatherThanRaised()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        harness.MagicLinkNotifier.ThrowOnSend = new InvalidOperationException("the relay is down");

        var outcome = await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.NotificationFailed);
    }

    // A relay that stops answering raises TaskCanceledException on its own timeout, which is not
    // this request being cancelled and must not escape as one.
    [Test]
    public async Task ANotifierThatTimesOutIsReportedRatherThanRaised()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        harness.MagicLinkNotifier.ThrowOnSend = new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.");

        var outcome = await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(MagicLinkRequestOutcome.NotificationFailed);
    }

    [Test]
    public async Task RequestingWithoutTheNotifierRegisteredThrows()
    {
        var harness = PasswordHarness.Create(withMagicLinkNotifier: false);
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        await Assert.That(async () => await harness.Accounts.RequestMagicLinkAsync("nic@example.com"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AskingForASecondLinkRetiresTheFirst()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await VerifyEmailAsync(harness, user);

        await harness.Accounts.RequestMagicLinkAsync("nic@example.com");
        await harness.Accounts.RequestMagicLinkAsync("nic@example.com");

        var first = harness.MagicLinkNotifier.Sent[0].Token;
        var result = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = first });

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidMagicLink);
    }

    // ── Redeeming one ──

    [Test]
    public async Task RedeemingIssuesATokenPair()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var token = await IssueLinkAsync(harness, user);

        var result = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.Tokens!.RefreshToken).IsNotEmpty();
    }

    // The claim the issue asks for, and the one a policy reads. pwd is absent because no password
    // was presented, which is the whole difference between this and /auth/login.
    [Test]
    public async Task TheIssuedTokenSaysEmailAndNotPwd()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var token = await IssueLinkAsync(harness, user);

        await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        var methods = harness.Issuer.Issued[^1].AuthenticationMethods;
        await Assert.That(methods).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(methods).DoesNotContain("pwd");
    }

    /// <summary>
    /// The rule that has been the bug three phases running: a claim that sign-in gets right and
    /// refresh recomputes goes wrong one access-token lifetime later, where it reads as a policy
    /// failure rather than a refresh failure.
    /// </summary>
    [Test]
    public async Task ARefreshedMagicLinkSessionStillSaysEmail()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var token = await IssueLinkAsync(harness, user);

        var signedIn = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });
        var refreshed = await harness.SignIn.RefreshAsync(signedIn.Tokens!.RefreshToken);

        await Assert.That(refreshed.Succeeded).IsTrue();

        var methods = harness.Issuer.Issued[^1].AuthenticationMethods;
        await Assert.That(methods).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(methods).DoesNotContain("pwd");
    }

    [Test]
    public async Task ALinkWorksOnce()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var token = await IssueLinkAsync(harness, user);

        await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });
        var second = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        await Assert.That(second.Outcome).IsEqualTo(SignInOutcome.InvalidMagicLink);
    }

    [Test]
    public async Task AnExpiredLinkIsRefused()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var token = await IssueLinkAsync(harness, user);

        harness.Clock.Now += harness.Options.MagicLinkTokenLifetime + TimeSpan.FromSeconds(1);

        var result = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidMagicLink);
    }

    [Test]
    public async Task AnUnknownTokenIsRefused()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = "not-a-real-token" });

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidMagicLink);
    }

    // ── Two-factor enforcement ──

    [Test]
    public async Task AnEnrolledAccountIsChallengedRatherThanSignedIn()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var token = await IssueLinkAsync(harness, user);
        var result = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await Assert.That(result.Tokens).IsNull();
    }

    // The first factor is carried on the challenge rather than assumed, so finishing one that a
    // magic link started does not put pwd on the token.
    [Test]
    public async Task FinishingTheChallengeSaysEmailOtpMfa()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var token = await IssueLinkAsync(harness, user);
        var challenged = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        harness.Clock.Now += harness.TwoFactorOptions.Period;

        var result = await harness.VerifyAsync(challenged.Challenge!.Token, harness.CurrentCode(secret));

        await Assert.That(result.Succeeded).IsTrue();

        var methods = harness.Issuer.Issued[^1].AuthenticationMethods;
        await Assert.That(methods).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(methods).Contains("otp");
        await Assert.That(methods).Contains(ToamaisutaaDefaults.MultiFactorMethod);
        await Assert.That(methods).DoesNotContain("pwd");
    }

    // The other side of the same change: an ordinary password sign-in still says pwd, which is the
    // thing carrying the methods on the challenge could quietly have broken.
    [Test]
    public async Task APasswordChallengeStillSaysPwdOtpMfa()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var challenged = await harness.SignInAsync("pianonic", "correct horse battery");

        harness.Clock.Now += harness.TwoFactorOptions.Period;

        var result = await harness.VerifyAsync(challenged.Challenge!.Token, harness.CurrentCode(secret));

        await Assert.That(result.Succeeded).IsTrue();

        var methods = harness.Issuer.Issued[^1].AuthenticationMethods;
        await Assert.That(methods).Contains("pwd");
        await Assert.That(methods).DoesNotContain(ToamaisutaaDefaults.MagicLinkMethod);
    }

    // A link spends itself on the way to the challenge. Anything else leaves a live credential in a
    // mailbox that has already been read once.
    [Test]
    public async Task ALinkThatReachedAChallengeIsAlreadySpent()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var token = await IssueLinkAsync(harness, user);
        await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        var again = await harness.SignIn.VerifyMagicLinkAsync(new MagicLinkSignInRequest { Token = token });

        await Assert.That(again.Outcome).IsEqualTo(SignInOutcome.InvalidMagicLink);
    }

    /// <summary>Proves the registered address, which is what a magic link requires. Re-verifying the
    /// address an account already has is the documented way to do it.</summary>
    private static async Task VerifyEmailAsync(PasswordHarness harness, ToamaisutaaUser user)
    {
        await harness.Accounts.RequestEmailChangeAsync(user.Id, user.Email!, "correct horse battery");
        await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent[^1].Token);
    }

    private static async Task<string> IssueLinkAsync(PasswordHarness harness, ToamaisutaaUser user)
    {
        await VerifyEmailAsync(harness, user);
        await harness.Accounts.RequestMagicLinkAsync(user.Email!);

        return harness.MagicLinkNotifier.Sent[^1].Token;
    }
}
