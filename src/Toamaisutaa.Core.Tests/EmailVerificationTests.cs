using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class EmailVerificationTests
{
    // ── Requesting a change ──

    [Test]
    public async Task RequestingAChangeSendsToTheNewAddressAndMovesNothingYet()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var result = await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");

        await Assert.That(result.Succeeded).IsTrue();

        // The whole mechanism: the link goes where the account is not yet.
        var sent = harness.EmailVerificationNotifier.Sent.Single();
        await Assert.That(sent.Email).IsEqualTo("moved@example.com");
        await Assert.That(sent.UserId).IsEqualTo(user.Id);

        var credential = harness.Passwords.Credentials.Single();
        await Assert.That(credential.Email).IsEqualTo("nic@example.com");
        await Assert.That(credential.EmailConfirmedAt).IsNull();
    }

    [Test]
    public async Task TheStoredVerificationTokenIsAHashOfWhatWasSent()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");

        var raw = harness.EmailVerificationNotifier.Sent.Single().Token;
        await Assert.That(harness.Passwords.EmailVerificationTokens.Single().TokenHash).IsNotEqualTo(raw);
    }

    [Test]
    public async Task RequestingAChangeWithTheWrongPasswordIsRefusedAndSendsNothing()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var result = await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "not the password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.EmailVerificationNotifier.Sent).IsEmpty();
        await Assert.That(harness.Passwords.EmailVerificationTokens).IsEmpty();
    }

    [Test]
    public async Task RequestingAnAddressAnotherLocalAccountHoldsIsAConflict()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.RegisterAsync("grace", "grace@example.com", "another whole password");

        var result = await harness.Accounts.RequestEmailChangeAsync(user.Id, "grace@example.com", "correct horse battery");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Conflict).IsTrue();
        await Assert.That(harness.EmailVerificationNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task AnAccountWithNoLocalCredentialCannotChangeItsEmailHere()
    {
        var harness = PasswordHarness.Create();
        var user = harness.ProvisionExternalUser();

        var result = await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "whatever");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.EmailVerificationNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task RequestingAChangeWithoutTheNotifierRegisteredThrows()
    {
        var harness = PasswordHarness.Create(withEmailVerificationNotifier: false);
        var user = await harness.RegisterAsync();

        await Assert.That(async () => await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AskingForASecondAddressRetiresTheLinkSentToTheFirst()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.RequestEmailChangeAsync(user.Id, "first@example.com", "correct horse battery");
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "second@example.com", "correct horse battery");

        var first = harness.EmailVerificationNotifier.Sent[0].Token;
        var result = await harness.Accounts.VerifyEmailAsync(first);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.Passwords.Credentials.Single().Email).IsEqualTo("nic@example.com");
    }

    // ── Redeeming ──

    [Test]
    public async Task RedeemingWritesTheAddressAndStampsItConfirmed()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");

        var result = await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That(result.Succeeded).IsTrue();

        var credential = harness.Passwords.Credentials.Single();
        await Assert.That(credential.Email).IsEqualTo("moved@example.com");
        await Assert.That(credential.NormalizedEmail).IsEqualTo("MOVED@EXAMPLE.COM");
        await Assert.That(credential.EmailConfirmedAt).IsEqualTo(harness.Clock.GetUtcNow());
    }

    // The profile field the notifiers address their mail to has to follow, or the next reset link
    // goes to the address this person just moved away from.
    [Test]
    public async Task RedeemingMovesTheEmailOnTheUserRowToo()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");

        await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That(harness.Users.Users.Single().Email).IsEqualTo("moved@example.com");
    }

    [Test]
    public async Task TheNewAddressSignsIn()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");
        await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That((await harness.SignInAsync("moved@example.com", "correct horse battery")).Outcome)
            .IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That((await harness.SignInAsync("nic@example.com", "correct horse battery")).Outcome)
            .IsEqualTo(SignInOutcome.UnknownUser);
    }

    [Test]
    public async Task AVerificationTokenIsSingleUse()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");
        var token = harness.EmailVerificationNotifier.Sent.Single().Token;

        await harness.Accounts.VerifyEmailAsync(token);
        var second = await harness.Accounts.VerifyEmailAsync(token);

        await Assert.That(second.Succeeded).IsFalse();
    }

    [Test]
    public async Task AnExpiredVerificationTokenIsRefused()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "moved@example.com", "correct horse battery");

        harness.Clock.Now += harness.Options.EmailVerificationTokenLifetime + TimeSpan.FromMinutes(1);

        var result = await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.Passwords.Credentials.Single().EmailConfirmedAt).IsNull();
    }

    [Test]
    public async Task AnUnknownVerificationTokenIsRefused()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.Accounts.VerifyEmailAsync("not-a-real-token");

        await Assert.That(result.Succeeded).IsFalse();
    }

    // The link can sit in a mailbox for a day, and somebody else can take the address in the
    // meantime. Checked again rather than left to the unique index.
    [Test]
    public async Task AnAddressTakenWhileTheLinkWaitedIsAConflict()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "contested@example.com", "correct horse battery");

        await harness.RegisterAsync("grace", "contested@example.com", "another whole password");

        var result = await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Conflict).IsTrue();
        await Assert.That(harness.Passwords.Credentials.First(credential => credential.UserId == user.Id).Email)
            .IsEqualTo("nic@example.com");
    }

    // A password change is the moment someone is most likely reacting to a break-in, and a pending
    // change of address is a credential in flight.
    [Test]
    public async Task ChangingThePasswordRetiresAnOutstandingVerificationLink()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "attacker@example.com", "correct horse battery");

        await harness.Accounts.SetPasswordAsync(user.Id, "correct horse battery", "a whole new password");

        var result = await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.Passwords.Credentials.Single().Email).IsEqualTo("nic@example.com");
    }

    // ── Requiring a verified address before a reset ──

    [Test]
    public async Task AnUnverifiedAddressIsSilentWhenTheOptionIsOn()
    {
        var harness = PasswordHarness.Create(options => options.RequireVerifiedEmailForPasswordReset = true);
        await harness.RegisterAsync();

        var outcome = await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.EmailNotVerified);
        await Assert.That(harness.Notifier.Sent).IsEmpty();
        await Assert.That(harness.Passwords.ResetTokens).IsEmpty();
    }

    [Test]
    public async Task AVerifiedAddressStillGetsAResetLinkWhenTheOptionIsOn()
    {
        var harness = PasswordHarness.Create(options => options.RequireVerifiedEmailForPasswordReset = true);
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestEmailChangeAsync(user.Id, "nic@example.com", "correct horse battery");
        await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent.Single().Token);

        var outcome = await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.Sent);
        await Assert.That(harness.Notifier.Sent.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AnUnverifiedAddressGetsAResetLinkWhileTheOptionIsOff()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var outcome = await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.Sent);
    }
}
