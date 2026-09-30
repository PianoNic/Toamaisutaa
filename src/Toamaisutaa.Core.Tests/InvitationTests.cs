using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class InvitationTests
{
    [Test]
    public async Task CreatingAnInvitationReservesAnAccountWithNoUserNameAndNoCredential()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.CreateInvitationAsync("ada@example.com");

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.Tokens).IsNull();

        var user = harness.Users.Users.Single();
        await Assert.That(user.Email).IsEqualTo("ada@example.com");
        await Assert.That(user.UserName).IsNull();
        await Assert.That(harness.Passwords.Credentials).IsEmpty();
    }

    [Test]
    public async Task CreatingAnInvitationHandsTheTokenToTheNotifierAndNeverReturnsIt()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.CreateInvitationAsync("ada@example.com");

        await Assert.That(harness.InvitationNotifier.Sent.Count).IsEqualTo(1);
        await Assert.That(harness.InvitationNotifier.Sent[0].UserId).IsEqualTo(result.UserId!.Value);
        await Assert.That(harness.InvitationNotifier.Sent[0].Token).IsNotEmpty();
    }

    // Nothing looks for an existing reservation before making one, so a row left behind by a failed
    // send would be reserved again by every retry.
    [Test]
    public async Task ANotifierFailureLeavesNoReservedAccountBehind()
    {
        var harness = PasswordHarness.Create();
        harness.InvitationNotifier.ThrowOnSend = new InvalidOperationException("the mail server is down");

        var result = await harness.Accounts.CreateInvitationAsync("ada@example.com");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.NotificationFailed).IsTrue();
        await Assert.That(harness.Users.Users).IsEmpty();
        await Assert.That(harness.Passwords.InvitationTokens.Where(token => token.ConsumedAt is null)).IsEmpty();
    }

    [Test]
    public async Task ARetryAfterANotifierFailureReservesExactlyOneAccount()
    {
        var harness = PasswordHarness.Create();
        harness.InvitationNotifier.ThrowOnSend = new InvalidOperationException("the mail server is down");
        await harness.Accounts.CreateInvitationAsync("ada@example.com");

        harness.InvitationNotifier.ThrowOnSend = null;
        var retry = await harness.Accounts.CreateInvitationAsync("ada@example.com");

        await Assert.That(retry.Succeeded).IsTrue();
        await Assert.That(harness.Users.Users.Count).IsEqualTo(1);
        await Assert.That(harness.Users.Users.Single().Id).IsEqualTo(retry.UserId!.Value);
    }

    [Test]
    public async Task CreatingAnInvitationWithoutTheNotifierRegisteredThrows()
    {
        var harness = PasswordHarness.Create(withInvitationNotifier: false);

        await Assert.That(async () => await harness.Accounts.CreateInvitationAsync("ada@example.com"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CompletingAnInvitationSetsTheChosenUserNameAndPasswordAndSignsIn()
    {
        var harness = PasswordHarness.Create();
        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var token = harness.InvitationNotifier.Sent.Single().Token;

        var result = await harness.Accounts.CompleteInvitationAsync(token, "ada", "correct horse battery");

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.Tokens).IsNotNull();

        var user = harness.Users.Users.Single();
        await Assert.That(user.UserName).IsEqualTo("ada");

        var signIn = await harness.SignInAsync("ada", "correct horse battery");
        await Assert.That(signIn.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task ATokenWorksOnlyOnce()
    {
        var harness = PasswordHarness.Create();
        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var token = harness.InvitationNotifier.Sent.Single().Token;
        await harness.Accounts.CompleteInvitationAsync(token, "ada", "correct horse battery");

        var second = await harness.Accounts.CompleteInvitationAsync(token, "someoneelse", "a different password");

        await Assert.That(second.Succeeded).IsFalse();
    }

    [Test]
    public async Task AnUnknownTokenFails()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.CompleteInvitationAsync("not-a-real-token", "ada", "correct horse battery");

        await Assert.That(result.Succeeded).IsFalse();
    }

    [Test]
    public async Task AnExpiredTokenFails()
    {
        var harness = PasswordHarness.Create(configure: options => options.InvitationTokenLifetime = TimeSpan.FromMinutes(30));
        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var token = harness.InvitationNotifier.Sent.Single().Token;

        harness.Clock.Now = harness.Clock.Now.AddHours(1);

        var result = await harness.Accounts.CompleteInvitationAsync(token, "ada", "correct horse battery");

        await Assert.That(result.Succeeded).IsFalse();
    }

    [Test]
    public async Task ATakenUserNameLeavesTheTokenUsable()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync("pianonic");
        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var token = harness.InvitationNotifier.Sent.Single().Token;

        var taken = await harness.Accounts.CompleteInvitationAsync(token, "pianonic", "correct horse battery");
        await Assert.That(taken.Succeeded).IsFalse();
        await Assert.That(taken.Conflict).IsTrue();

        var retry = await harness.Accounts.CompleteInvitationAsync(token, "ada", "correct horse battery");
        await Assert.That(retry.Succeeded).IsTrue();
    }

    [Test]
    public async Task CompletingAnInvitationNeverCallsTheAdminPasswordNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var token = harness.InvitationNotifier.Sent.Single().Token;

        await harness.Accounts.CompleteInvitationAsync(token, "ada", "correct horse battery");

        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
    }

    [Test]
    public async Task RegisteringNeverCallsTheInvitationNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await Assert.That(harness.InvitationNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task AdminCreatingAnAccountNeverCallsTheInvitationNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.Accounts.AdminCreateAccountAsync("ada", "ada@example.com", "correct horse battery");

        await Assert.That(harness.InvitationNotifier.Sent).IsEmpty();
    }
}
