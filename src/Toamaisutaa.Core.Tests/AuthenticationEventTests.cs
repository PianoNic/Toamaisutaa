using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class AuthenticationEventTests
{
    private const string Password = "correct horse battery";

    [Test]
    public async Task A_successful_sign_in_publishes_the_session_and_the_amr_values()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var published = harness.Events.Single<SignInSucceeded>();

        await Assert.That(published.UserId).IsEqualTo(user.Id);
        await Assert.That(published.OccurredAt).IsEqualTo(harness.Clock.GetUtcNow());
        await Assert.That(published.AuthenticationMethods).Contains("pwd");
        await Assert.That(published.TwoFactorSource).IsNull();
        await Assert.That(published.SessionId).IsEqualTo(harness.Passwords.RefreshTokens[^1].FamilyId);
        await Assert.That(published.Kind).IsEqualTo("sign-in-succeeded");
    }

    [Test]
    public async Task A_wrong_password_publishes_a_failure_naming_the_account_and_the_reason()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.SignInAsync("pianonic", "not the password");

        var failure = harness.Events.Single<SignInFailed>();

        await Assert.That(failure.Reason).IsEqualTo(SignInOutcome.InvalidPassword);
        await Assert.That(failure.UserId).IsEqualTo(user.Id);
    }

    /// <summary>Must not name the identifier instead: people type their password into the user name box.</summary>
    [Test]
    public async Task An_identifier_nobody_owns_publishes_a_failure_that_names_no_account()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await harness.SignInAsync("nobody", Password);

        var failure = harness.Events.Single<SignInFailed>();

        await Assert.That(failure.Reason).IsEqualTo(SignInOutcome.UnknownUser);
        await Assert.That(failure.UserId).IsNull();
    }

    [Test]
    public async Task Only_the_attempt_that_crosses_the_threshold_publishes_a_lockout()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        for (var attempt = 0; attempt < 8; attempt++)
            await harness.SignInAsync("pianonic", "wrong");

        var lockout = harness.Events.Single<AccountLockedOut>();

        await Assert.That(lockout.UserId).IsEqualTo(user.Id);
        await Assert.That(lockout.LockedOutUntil).IsEqualTo(harness.Clock.GetUtcNow() + harness.Options.LockoutDuration);

        var reasons = harness.Events.OfKind<SignInFailed>().Select(failure => failure.Reason).ToList();

        await Assert.That(reasons.Count(reason => reason == SignInOutcome.InvalidPassword)).IsEqualTo(5);
        await Assert.That(reasons.Count(reason => reason == SignInOutcome.LockedOut)).IsEqualTo(3);
    }

    [Test]
    public async Task Refreshing_publishes_no_sign_in()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        await harness.SignIn.RefreshAsync(tokens.RefreshToken);

        await Assert.That(harness.Events.OfKind<SignInSucceeded>().Count).IsEqualTo(2);
    }

    [Test]
    public async Task Signing_out_publishes_the_revocation_with_its_reason()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        var session = harness.Passwords.RefreshTokens[^1].FamilyId;

        await harness.SignIn.SignOutAsync(tokens.RefreshToken);

        var revoked = harness.Events.Single<SessionRevoked>();

        await Assert.That(revoked.UserId).IsEqualTo(user.Id);
        await Assert.That(revoked.SessionId).IsEqualTo(session);
        await Assert.That(revoked.Reason).IsEqualTo("signed-out");
    }

    [Test]
    public async Task Refresh_token_reuse_publishes_the_detection_and_the_revocation()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        var tokens = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        var session = harness.Passwords.RefreshTokens[^1].FamilyId;

        await harness.SignIn.RefreshAsync(tokens.RefreshToken);
        await harness.SignIn.RefreshAsync(tokens.RefreshToken);

        var detected = harness.Events.Single<RefreshTokenReuseDetected>();

        await Assert.That(detected.UserId).IsEqualTo(user.Id);
        await Assert.That(detected.SessionId).IsEqualTo(session);

        var revoked = harness.Events.Single<SessionRevoked>();

        await Assert.That(revoked.SessionId).IsEqualTo(session);
        await Assert.That(revoked.Reason).IsEqualTo("refresh-token-reuse");
    }

    [Test]
    public async Task Changing_a_password_publishes_the_change_and_the_sessions_it_ended()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.SetPasswordAsync(user.Id, Password, "a whole new passphrase");

        var changed = harness.Events.Single<PasswordChanged>();

        await Assert.That(changed.UserId).IsEqualTo(user.Id);
        await Assert.That(changed.SetByAdministrator).IsFalse();

        var revoked = harness.Events.Single<SessionRevoked>();

        await Assert.That(revoked.SessionId).IsNull();
        await Assert.That(revoked.Reason).IsEqualTo("password-changed");
    }

    [Test]
    public async Task An_administrator_setting_a_password_says_so()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.AdminSetPasswordAsync(user.Id, "issued by the gate master");

        await Assert.That(harness.Events.Single<PasswordChanged>().SetByAdministrator).IsTrue();
    }

    [Test]
    public async Task Completing_a_reset_publishes_a_reset_rather_than_a_change()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        await harness.Accounts.ResetPasswordAsync(harness.Notifier.Sent[^1].Token, "a whole new passphrase");

        var reset = harness.Events.Single<PasswordReset>();

        await Assert.That(reset.UserId).IsEqualTo(user.Id);
        await Assert.That(harness.Events.OfKind<PasswordChanged>()).IsEmpty();
    }

    [Test]
    public async Task Redeeming_a_verification_link_publishes_where_the_address_moved_from_and_to()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.RegisterAsync();

        await harness.Accounts.RequestEmailChangeAsync(user.Id, "somebody.else@example.com", Password);
        await harness.Accounts.VerifyEmailAsync(harness.EmailVerificationNotifier.Sent[^1].Token);

        var changed = harness.Events.Single<EmailChanged>();

        await Assert.That(changed.UserId).IsEqualTo(user.Id);
        await Assert.That(changed.PreviousEmail).IsEqualTo("nic@example.com");
        await Assert.That(changed.Email).IsEqualTo("somebody.else@example.com");
        await Assert.That(changed.Kind).IsEqualTo("email-changed");
    }

    [Test]
    public async Task Confirming_and_disabling_an_enrolment_publish_both_ends_of_it()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();

        var (secret, _) = await harness.EnrolAsync(user.Id);

        await Assert.That(harness.Events.Single<TwoFactorEnrolled>().UserId).IsEqualTo(user.Id);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));

        await Assert.That(harness.Events.Single<TwoFactorDisabled>().UserId).IsEqualTo(user.Id);

        var reasons = harness.Events.OfKind<SessionRevoked>().Select(revoked => revoked.Reason).ToList();

        await Assert.That(reasons).Contains("two-factor-enabled");
        await Assert.That(reasons).Contains("two-factor-disabled");
    }

    [Test]
    public async Task A_wrong_code_publishes_a_two_factor_failure_that_still_names_the_account()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();

        await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        await harness.VerifyAsync(started.Challenge!.Token, "000000");

        var failure = harness.Events.Single<TwoFactorFailed>();

        await Assert.That(failure.Reason).IsEqualTo(SignInOutcome.InvalidTwoFactorCode);
        await Assert.That(failure.UserId).IsEqualTo(user.Id);
    }

    [Test]
    public async Task A_wrong_proof_for_disabling_a_second_factor_publishes_a_failure()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();

        await harness.EnrolAsync(user.Id);

        var result = await harness.TwoFactor.DisableAsync(user.Id, "000000");

        await Assert.That(result.Succeeded).IsFalse();

        var failure = harness.Events.Single<TwoFactorFailed>();

        await Assert.That(failure.UserId).IsEqualTo(user.Id);
        await Assert.That(failure.Reason).IsEqualTo(SignInOutcome.InvalidTwoFactorCode);
        await Assert.That(harness.Events.OfKind<TwoFactorDisabled>()).IsEmpty();
    }

    [Test]
    public async Task A_recovery_code_spent_to_disable_a_second_factor_is_published_as_one()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();

        var (_, codes) = await harness.EnrolAsync(user.Id);

        var result = await harness.TwoFactor.DisableAsync(user.Id, codes[0]);

        await Assert.That(result.Succeeded).IsTrue();

        var used = harness.Events.Single<RecoveryCodeUsed>();

        await Assert.That(used.UserId).IsEqualTo(user.Id);
        await Assert.That(harness.Events.Single<TwoFactorDisabled>().UserId).IsEqualTo(user.Id);
    }

    [Test]
    public async Task A_wrong_step_up_code_publishes_the_failure_and_the_lockout_it_crosses()
    {
        var harness = PasswordHarness.Create(options => options.MaxFailedAttempts = 2, withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        var sessionId = harness.Issuer.Issued[^1].SessionId!.Value;

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var challenge = await harness.SignIn.BeginStepUpAsync(new StepUpRequest { UserId = user.Id, SessionId = sessionId });

            await harness.SignIn.CompleteStepUpAsync(new StepUpVerificationRequest
            {
                UserId = user.Id,
                SessionId = sessionId,
                ChallengeToken = challenge.Challenge!.Token,
                Code = "000000",
            });
        }

        var failures = harness.Events.OfKind<TwoFactorFailed>();

        await Assert.That(failures.Count).IsEqualTo(2);
        await Assert.That(failures[0].UserId).IsEqualTo(user.Id);
        await Assert.That(failures[0].Reason).IsEqualTo(SignInOutcome.InvalidTwoFactorCode);

        var lockout = harness.Events.Single<AccountLockedOut>();

        await Assert.That(lockout.UserId).IsEqualTo(user.Id);
        await Assert.That(lockout.LockedOutUntil).IsEqualTo(harness.Clock.GetUtcNow() + harness.Options.LockoutDuration);
    }

    [Test]
    public async Task Spending_a_recovery_code_is_published_as_its_own_event()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();

        var (_, codes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        await harness.VerifyAsync(started.Challenge!.Token, codes[0]);

        var used = harness.Events.Single<RecoveryCodeUsed>();

        await Assert.That(used.UserId).IsEqualTo(user.Id);
        await Assert.That(used.RunningLow).IsFalse();

        var signedIn = harness.Events.OfKind<SignInSucceeded>()[^1];

        await Assert.That(signedIn.TwoFactorSource).IsEqualTo(TwoFactorSource.Recovery);
        await Assert.That(signedIn.AuthenticationMethods).Contains(ToamaisutaaDefaults.MultiFactorMethod);
    }

    [Test]
    public async Task Trusting_a_device_and_revoking_it_are_both_published()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true, withTrustedDevices: true);
        var user = await harness.RegisterAsync();

        var (secret, _) = await harness.EnrolAsync(user.Id);
        var started = await harness.SignInAsync("pianonic", Password);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true, label: "the gate house");

        var added = harness.Events.Single<TrustedDeviceAdded>();

        await Assert.That(added.UserId).IsEqualTo(user.Id);
        await Assert.That(added.Label).IsEqualTo("the gate house");
        await Assert.That(added.DeviceId).IsEqualTo(harness.Devices.Devices[^1].FamilyId);

        await harness.TrustedDevices.RevokeAsync(user.Id, added.DeviceId);

        var revoked = harness.Events.Single<TrustedDeviceRevoked>();

        await Assert.That(revoked.DeviceId).IsEqualTo(added.DeviceId);
        await Assert.That(revoked.Reason).IsEqualTo("revoked-by-user");
    }

    [Test]
    public async Task A_password_change_publishes_one_device_revocation_for_the_whole_account()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true, withTrustedDevices: true);
        var user = await harness.RegisterAsync();

        var (secret, _) = await harness.EnrolAsync(user.Id);
        var started = await harness.SignInAsync("pianonic", Password);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true);

        await harness.Accounts.SetPasswordAsync(user.Id, Password, "a whole new passphrase");

        var revoked = harness.Events.OfKind<TrustedDeviceRevoked>().Single(entry => entry.Reason == "password-changed");

        await Assert.That(revoked.DeviceId).IsNull();
        await Assert.That(revoked.UserId).IsEqualTo(user.Id);
    }

    [Test]
    public async Task A_sink_that_throws_neither_fails_the_flow_nor_stops_the_next_sink()
    {
        var harness = PasswordHarness.Create(withThrowingEventSink: true);
        await harness.RegisterAsync();

        var result = await harness.SignInAsync("pianonic", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(result.Tokens).IsNotNull();
        await Assert.That(harness.Events.OfKind<SignInSucceeded>()).IsNotEmpty();
    }
}
