using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class PasswordAccountServiceTests
{
    private const string Password = "correct horse battery";

    [Test]
    public async Task RegisteringCreatesAUserACredentialAndSignsIn()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.RegisterAsync(new RegisterRequest("pianonic", "nic@example.com", Password));

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(harness.Users.Users.Count).IsEqualTo(1);
        await Assert.That(harness.Passwords.Credentials.Count).IsEqualTo(1);
        await Assert.That(result.Tokens).IsNotNull();
        await Assert.That(harness.Passwords.Credentials.Single().NormalizedUserName).IsEqualTo("PIANONIC");
        await Assert.That(harness.Passwords.Credentials.Single().NormalizedEmail).IsEqualTo("NIC@EXAMPLE.COM");
    }

    [Test]
    public async Task ThePasswordIsNeverStoredInTheClear()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var stored = harness.Passwords.Credentials.Single().PasswordHash;

        await Assert.That(stored).DoesNotContain(Password);
        await Assert.That(stored).StartsWith("$pbkdf2-sha256$");
    }

    [Test]
    [Arguments("PIANONIC", null)]
    [Arguments("someoneelse", "NIC@example.com")]
    public async Task ATakenIdentifierIsRejectedRegardlessOfCase(string userName, string? email)
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.Accounts.RegisterAsync(new RegisterRequest(userName, email, Password));

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Conflict).IsTrue();
    }

    // A collision must not leave an account behind that nobody can sign in to.
    [Test]
    public async Task ARejectedRegistrationLeavesNoUserRow()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await harness.Accounts.RegisterAsync(new RegisterRequest("pianonic", "other@example.com", Password));

        await Assert.That(harness.Users.Users.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AShortPasswordIsRejectedBeforeAnythingIsWritten()
    {
        var harness = PasswordHarness.Create();

        var result = await harness.Accounts.RegisterAsync(new RegisterRequest("pianonic", "nic@example.com", "short"));

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(harness.Users.Users).IsEmpty();
        await Assert.That(harness.Passwords.Credentials).IsEmpty();
    }

    // ── Setting a password on an account that came from an identity provider ──

    [Test]
    public async Task AnExternalAccountCanBeGivenAPasswordAndThenUsesIt()
    {
        var harness = PasswordHarness.Create();
        var user = harness.ProvisionExternalUser();

        var result = await harness.Accounts.SetPasswordAsync(user.Id, currentPassword: null, Password);

        await Assert.That(result.Succeeded).IsTrue();

        var signIn = await harness.SignInAsync("ssouser", Password);
        await Assert.That(signIn.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task GivingACurrentPasswordToAnAccountThatHasNoneIsRefused()
    {
        var harness = PasswordHarness.Create();
        var user = harness.ProvisionExternalUser();

        var result = await harness.Accounts.SetPasswordAsync(user.Id, "anything", Password);

        await Assert.That(result.Succeeded).IsFalse();
    }

    [Test]
    public async Task ChangingAPasswordNeedsTheCurrentOne()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var withoutIt = await harness.Accounts.SetPasswordAsync(user.Id, null, "a whole new password");
        var wrongOne = await harness.Accounts.SetPasswordAsync(user.Id, "not it", "a whole new password");

        await Assert.That(withoutIt.Succeeded).IsFalse();
        await Assert.That(wrongOne.Succeeded).IsFalse();
    }

    [Test]
    public async Task ChangingAPasswordEndsEveryOtherSession()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;

        await harness.Accounts.SetPasswordAsync(user.Id, Password, "a whole new password");

        var refreshed = await harness.SignIn.RefreshAsync(tokens.RefreshToken);
        await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);

        var oldPassword = await harness.SignInAsync("pianonic", Password);
        await Assert.That(oldPassword.Outcome).IsEqualTo(SignInOutcome.InvalidPassword);

        var newPassword = await harness.SignInAsync("pianonic", "a whole new password");
        await Assert.That(newPassword.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    // ── Reset ──

    [Test]
    public async Task RequestingAResetHandsATokenToTheNotifier()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var outcome = await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.Sent);
        await Assert.That(harness.Notifier.Sent.Count).IsEqualTo(1);

        // Stored hashed, exactly like a refresh token.
        await Assert.That(harness.Passwords.ResetTokens.Single().TokenHash).IsNotEqualTo(harness.Notifier.Sent[0].Token);
    }

    [Test]
    public async Task AnUnknownAddressIsSilent()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var outcome = await harness.Accounts.RequestPasswordResetAsync("nobody@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.UnknownEmail);
        await Assert.That(harness.Notifier.Sent).IsEmpty();
    }

    // The confusing case: a real person, no password here, and no email will ever arrive. The
    // outcome is the only way anyone diagnoses it.
    [Test]
    public async Task AnAccountOwnedByAnIdentityProviderIsSilentButDistinctInTheLog()
    {
        var harness = PasswordHarness.Create();
        harness.ProvisionExternalUser("sso@example.com");

        var outcome = await harness.Accounts.RequestPasswordResetAsync("sso@example.com");

        await Assert.That(outcome).IsEqualTo(PasswordResetRequestOutcome.NoLocalCredential);
        await Assert.That(harness.Notifier.Sent).IsEmpty();
        await Assert.That(harness.Passwords.ResetTokens).IsEmpty();
    }

    [Test]
    public async Task AResetTokenSetsTheNewPassword()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        var token = harness.Notifier.Sent.Single().Token;
        var result = await harness.Accounts.ResetPasswordAsync(token, "a whole new password");

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That((await harness.SignInAsync("pianonic", "a whole new password")).Outcome)
            .IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task AResetTokenWorksOnlyOnce()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        var token = harness.Notifier.Sent.Single().Token;
        await harness.Accounts.ResetPasswordAsync(token, "a whole new password");

        var second = await harness.Accounts.ResetPasswordAsync(token, "yet another password");

        await Assert.That(second.Succeeded).IsFalse();
    }

    [Test]
    public async Task AnExpiredResetTokenIsRefused()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        harness.Clock.Now = harness.Clock.Now + harness.Options.PasswordResetTokenLifetime + TimeSpan.FromSeconds(1);

        var result = await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent.Single().Token, "a whole new password");

        await Assert.That(result.Succeeded).IsFalse();
    }

    [Test]
    public async Task AskingForASecondLinkRetiresTheFirst()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");

        var first = await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent[0].Token, "a whole new password");
        var second = await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent[1].Token, "a whole new password");

        await Assert.That(first.Succeeded).IsFalse();
        await Assert.That(second.Succeeded).IsTrue();
    }

    [Test]
    public async Task AResetEndsEveryLocalSession()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent.Single().Token, "a whole new password");

        var refreshed = await harness.SignIn.RefreshAsync(tokens.RefreshToken);

        await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);
    }

    // A reset is about the local credential and nothing else. The identity provider's side of the
    // account is not ours to touch.
    [Test]
    public async Task AResetLeavesTheExternalSideAlone()
    {
        var harness = PasswordHarness.Create();
        var user = harness.ProvisionExternalUser("both@example.com", "bothuser");

        harness.Users.Logins.Add(new ToamaisutaaExternalLogin
        {
            Id = Guid.CreateVersion7(harness.Clock.GetUtcNow()),
            UserId = user.Id,
            ProviderKey = ToamaisutaaDefaults.ProviderKey,
            Subject = "external-subject",
            CreatedAt = harness.Clock.GetUtcNow(),
        });

        await harness.Accounts.SetPasswordAsync(user.Id, null, Password);
        await harness.Accounts.RequestPasswordResetAsync("both@example.com");
        await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent.Single().Token, "a whole new password");

        var login = harness.Users.Logins.Single();

        await Assert.That(login.UserId).IsEqualTo(user.Id);
        await Assert.That(login.Subject).IsEqualTo("external-subject");
        await Assert.That(harness.Users.Logins.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AResetGivesTheAccountBackToSomeoneWhoWasLockedOut()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        for (var attempt = 0; attempt < 5; attempt++)
            await harness.SignInAsync("pianonic", "wrong");

        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent.Single().Token, "a whole new password");

        var result = await harness.SignInAsync("pianonic", "a whole new password");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }
}
