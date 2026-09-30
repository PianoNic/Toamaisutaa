using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class AdminAccountTests
{
    private const string Password = "correct horse battery";

    [Test]
    public async Task CreatingAnAccountWithAChosenPasswordHandsItToTheNotifierAndNeverSignsIn()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.AdminCreateAccountAsync("ada", "ada@example.com", Password);

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.Tokens).IsNull();
        await Assert.That(harness.AdminPasswordNotifier.Issued.Count).IsEqualTo(1);
        await Assert.That(harness.AdminPasswordNotifier.Issued[0].UserId).IsEqualTo(result.UserId!.Value);
        await Assert.That(harness.AdminPasswordNotifier.Issued[0].Password).IsEqualTo(Password);

        var signIn = await harness.SignInAsync("ada", Password);
        await Assert.That(signIn.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    /// <summary>A user name shaped like an address holds that address in the one column proving the
    /// mailbox cannot release.</summary>
    [Test]
    public async Task AUserNameShapedLikeAnAddressIsRefusedWhereverOneIsChosen()
    {
        var harness = PasswordHarness.Create();

        var created = await harness.Accounts.AdminCreateAccountAsync("newhire@example.com", null, Password);

        await harness.Accounts.CreateInvitationAsync("ada@example.com");
        var completed = await harness.Accounts.CompleteInvitationAsync(harness.InvitationNotifier.Sent[0].Token, "newhire@example.com", Password);

        await Assert.That(created.Succeeded).IsFalse();
        await Assert.That(completed.Succeeded).IsFalse();
        await Assert.That(harness.Passwords.Credentials).IsEmpty();
    }

    /// <summary>A display name in front of the address rides into the To header and the mail body.</summary>
    [Test]
    public async Task AnAddressWithADisplayNameIsRefusedForANewAccount()
    {
        var harness = PasswordHarness.Create();

        var created = await harness.Accounts.AdminCreateAccountAsync("ada", "\"Ada\" <ada@example.com>", Password);

        await Assert.That(created.Succeeded).IsFalse();
    }

    [Test]
    public async Task AnAddressWithADisplayNameIsRefusedForAnInvitation()
    {
        var harness = PasswordHarness.Create();

        var invited = await harness.Accounts.CreateInvitationAsync("\"Ada\" <ada@example.com>");

        await Assert.That(invited.Succeeded).IsFalse();
        await Assert.That(harness.InvitationNotifier.Sent).IsEmpty();
    }

    [Test]
    public async Task CreatingAnAccountWithNoPasswordGeneratesOneThatActuallySignsIn()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.AdminCreateAccountAsync("ada", "ada@example.com", password: null);

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(harness.AdminPasswordNotifier.Issued.Count).IsEqualTo(1);

        var generated = harness.AdminPasswordNotifier.Issued[0].Password;
        await Assert.That(generated).IsNotEmpty();

        var signIn = await harness.SignInAsync("ada", generated);
        await Assert.That(signIn.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task ANeverStoresTheGeneratedPasswordInTheClear()
    {
        var harness = PasswordHarness.Create();
        await harness.Accounts.AdminCreateAccountAsync("ada", "ada@example.com", password: null);

        var generated = harness.AdminPasswordNotifier.Issued[0].Password;

        await Assert.That(harness.Passwords.Credentials.Single().PasswordHash).DoesNotContain(generated);
    }

    [Test]
    public async Task ATakenUserNameIsRejectedAndTheNotifierIsNeverCalled()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.Accounts.AdminCreateAccountAsync("pianonic", "someone-else@example.com", Password);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Conflict).IsTrue();
        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
        await Assert.That(harness.Users.Users.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CreatingAnAccountWithoutTheNotifierRegisteredThrows()
    {
        var harness = PasswordHarness.Create(withAdminPasswordNotifier: false);

        await Assert.That(async () => await harness.Accounts.AdminCreateAccountAsync("ada", "ada@example.com", Password))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task SettingAPasswordForSomeoneElseNeedsNoCurrentPassword()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var result = await harness.Accounts.AdminSetPasswordAsync(user.Id, "a whole new password");

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(harness.AdminPasswordNotifier.Issued[0].Password).IsEqualTo("a whole new password");
    }

    [Test]
    public async Task SettingAPasswordEndsEveryOtherSession()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;

        await harness.Accounts.AdminSetPasswordAsync(user.Id, "a whole new password");

        var refreshed = await harness.SignIn.RefreshAsync(tokens.RefreshToken);
        await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);

        var oldPassword = await harness.SignInAsync("pianonic", Password);
        await Assert.That(oldPassword.Outcome).IsEqualTo(SignInOutcome.InvalidPassword);

        var newPassword = await harness.SignInAsync("pianonic", "a whole new password");
        await Assert.That(newPassword.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task SettingAPasswordWithNoneGivenGeneratesOne()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.AdminSetPasswordAsync(user.Id, password: null);

        var generated = harness.AdminPasswordNotifier.Issued[0].Password;
        await Assert.That(generated).IsNotEqualTo(Password);

        var signIn = await harness.SignInAsync("pianonic", generated);
        await Assert.That(signIn.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task SettingAPasswordOnAnAccountWithNoCredentialYetGivesItOne()
    {
        var harness = PasswordHarness.Create();
        var user = harness.ProvisionExternalUser();

        var result = await harness.Accounts.AdminSetPasswordAsync(user.Id, Password);

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(harness.Passwords.Credentials.Single().UserId).IsEqualTo(user.Id);
    }

    [Test]
    public async Task SettingAPasswordForAnUnknownUserFails()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.AdminSetPasswordAsync(Guid.NewGuid(), Password);

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
    }

    // The revocation is what an admin reset is for, so it may not depend on an SMTP relay being up.
    [Test]
    public async Task ANotifierFailureStillEndsEverySession()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        harness.AdminPasswordNotifier.ThrowOnSend = new InvalidOperationException("the mail server is down");

        var result = await harness.Accounts.AdminSetPasswordAsync(user.Id, "a whole new password");

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.NotificationFailed).IsTrue();

        var refreshed = await harness.SignIn.RefreshAsync(tokens.RefreshToken);
        await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);

        await Assert.That(harness.Passwords.ResetTokens.Single().ConsumedAt.HasValue).IsTrue();

        var newPassword = await harness.SignInAsync("pianonic", "a whole new password");
        await Assert.That(newPassword.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task ANotifierFailurePublishesThePasswordChangedEvent()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();
        harness.AdminPasswordNotifier.ThrowOnSend = new InvalidOperationException("the mail server is down");

        await harness.Accounts.AdminSetPasswordAsync(user.Id, "a whole new password");

        await Assert.That(harness.Events.Single<PasswordChanged>().SetByAdministrator).IsTrue();
    }

    [Test]
    public async Task SettingAPasswordWithoutTheNotifierRegisteredThrows()
    {
        var harness = PasswordHarness.Create(withAdminPasswordNotifier: false);
        var user = await harness.RegisterAsync();

        await Assert.That(async () => await harness.Accounts.AdminSetPasswordAsync(user.Id, Password))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RegisteringNeverCallsTheAdminNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
    }

    [Test]
    public async Task AVoluntaryPasswordChangeNeverCallsTheAdminNotifier()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.SetPasswordAsync(user.Id, Password, "a whole new password");

        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
    }

    [Test]
    public async Task ASelfServiceResetNeverCallsTheAdminNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        var token = harness.Notifier.Sent.Single().Token;

        await harness.Accounts.ResetPasswordAsync(token, "a whole new password");

        await Assert.That(harness.AdminPasswordNotifier.Issued).IsEmpty();
    }
}
