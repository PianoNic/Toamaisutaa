using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class TrustedDeviceTests
{
    private const string Password = "correct horse battery";

    private static PasswordHarness Harness(
        Action<ToamaisutaaTrustedDeviceOptions>? configure = null,
        Action<ToamaisutaaTwoFactorOptions>? configureTwoFactor = null) =>
        PasswordHarness.Create(
            configureTwoFactor: configureTwoFactor,
            configureTrustedDevices: configure,
            withTwoFactor: true,
            withTrustedDevices: true);

    /// <summary>Enrols, signs in, completes a live challenge asking to be remembered, and returns
    /// the device token.</summary>
    private static async Task<(ToamaisutaaUser User, byte[] Secret, string DeviceToken)> TrustedAsync(PasswordHarness harness)
    {
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var finished = await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true);

        if (finished.TrustedDevice is null)
            throw new InvalidOperationException("No device token was issued.");

        return (user, secret, finished.TrustedDevice.Token);
    }

    // ── The happy path ──

    [Test]
    public async Task A_trusted_device_skips_the_challenge()
    {
        var harness = Harness();
        var (_, _, deviceToken) = await TrustedAsync(harness);

        harness.Clock.Now = harness.Clock.Now.AddDays(1);
        var result = await harness.SignInAsync("pianonic", Password, deviceToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(result.Challenge).IsNull();
    }

    [Test]
    public async Task Without_the_device_token_the_same_user_is_still_challenged()
    {
        var harness = Harness();
        await TrustedAsync(harness);

        var result = await harness.SignInAsync("pianonic", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    /// <summary>
    /// D5. A cached factor is not a one-time password, and a consumer's policy will act on the claim.
    /// </summary>
    [Test]
    public async Task A_device_trusted_sign_in_claims_mfa_but_never_otp()
    {
        var harness = Harness();
        var (_, _, deviceToken) = await TrustedAsync(harness);

        var liveAt = harness.Clock.Now;
        harness.Clock.Now = harness.Clock.Now.AddDays(1);

        await harness.SignInAsync("pianonic", Password, deviceToken);

        var issued = harness.Issuer.Issued[^1];

        await Assert.That(issued.AuthenticationMethods).Contains("mfa");
        await Assert.That(issued.AuthenticationMethods).DoesNotContain("otp");
        await Assert.That(issued.TwoFactorSource).IsEqualTo(TwoFactorSource.Device);

        // The original live challenge, not now - which is what makes step-up expressible.
        await Assert.That(issued.SecondFactorAt).IsEqualTo(liveAt);
    }

    [Test]
    public async Task A_live_challenge_reports_otp_and_the_current_moment()
    {
        var harness = Harness();
        var (_, secret, _) = await TrustedAsync(harness);

        var issued = harness.Issuer.Issued[^1];

        await Assert.That(issued.TwoFactorSource).IsEqualTo(TwoFactorSource.Otp);
        await Assert.That(issued.SecondFactorAt).IsEqualTo(harness.Clock.Now);
        await Assert.That(secret.Length).IsGreaterThan(0);
    }

    // ── The loop that would defeat the absolute lifetime ──

    /// <summary>
    /// Present token, skip challenge, receive a fresh token. If that restarted the family, thirty
    /// days would mean "forever, as long as you sign in monthly".
    /// </summary>
    [Test]
    public async Task Using_a_trusted_device_does_not_extend_its_absolute_lifetime()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        var originalFamily = harness.Devices.Devices.Single().FamilyId;
        var originalStart = harness.Devices.Devices.Single().FamilyStartedAt;

        var token = deviceToken;

        for (var day = 0; day < 3; day++)
        {
            harness.Clock.Now = harness.Clock.Now.AddDays(1);
            var result = await harness.SignInAsync("pianonic", Password, token);

            await Assert.That(result.Succeeded).IsTrue();
            token = result.TrustedDevice!.Token;
        }

        var families = harness.Devices.Devices.Where(d => d.UserId == user.Id).Select(d => d.FamilyId).Distinct().ToList();

        await Assert.That(families.Count).IsEqualTo(1);
        await Assert.That(families[0]).IsEqualTo(originalFamily);
        await Assert.That(harness.Devices.Devices.All(d => d.FamilyStartedAt == originalStart)).IsTrue();
    }

    [Test]
    public async Task Past_the_absolute_lifetime_it_is_refused_despite_recent_use()
    {
        var harness = Harness(options => options.Lifetime = TimeSpan.FromDays(30));
        var (_, _, deviceToken) = await TrustedAsync(harness);

        var token = deviceToken;

        // Used every day, which under a sliding window would keep it alive forever.
        for (var day = 0; day < 29; day++)
        {
            harness.Clock.Now = harness.Clock.Now.AddDays(1);
            var ok = await harness.SignInAsync("pianonic", Password, token);
            token = ok.TrustedDevice!.Token;
        }

        harness.Clock.Now = harness.Clock.Now.AddDays(2);
        var result = await harness.SignInAsync("pianonic", Password, token);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    // ── Rotation and reuse ──

    [Test]
    public async Task A_rotated_device_token_presented_again_revokes_the_whole_family()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        harness.Clock.Now = harness.Clock.Now.AddHours(1);
        var first = await harness.SignInAsync("pianonic", Password, deviceToken);
        await Assert.That(first.Succeeded).IsTrue();

        // The old one, again.
        harness.Clock.Now = harness.Clock.Now.AddHours(1);
        var reused = await harness.SignInAsync("pianonic", Password, deviceToken);

        await Assert.That(reused.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);

        // And the token handed out by the successful rotation is dead too.
        harness.Clock.Now = harness.Clock.Now.AddHours(1);
        var sibling = await harness.SignInAsync("pianonic", Password, first.TrustedDevice!.Token);

        await Assert.That(sibling.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await Assert.That(harness.Devices.Devices.Where(d => d.UserId == user.Id).All(d => d.RevokedAt is not null)).IsTrue();
    }

    // ── D4: the eight revocations, one test each ──

    [Test]
    public async Task Revoked_by_a_password_change()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        await harness.Accounts.SetPasswordAsync(user.Id, Password, "an entirely new password");

        var result = await harness.SignInAsync("pianonic", "an entirely new password", deviceToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await AssertNoLiveDeviceAsync(harness, user.Id);
    }

    [Test]
    public async Task Revoked_by_a_password_reset()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        await harness.Accounts.RequestPasswordResetAsync("nic@example.com");
        var token = harness.Notifier.Sent[^1].Token;
        await harness.Accounts.ResetPasswordAsync(token, "an entirely new password");

        var result = await harness.SignInAsync("pianonic", "an entirely new password", deviceToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await AssertNoLiveDeviceAsync(harness, user.Id);
    }

    [Test]
    public async Task Revoked_when_two_factor_is_disabled()
    {
        var harness = Harness();
        var (user, secret, deviceToken) = await TrustedAsync(harness);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));

        // Nothing to challenge now, but the row must not survive as a live trust.
        await harness.SignInAsync("pianonic", Password, deviceToken);
        await AssertNoLiveDeviceAsync(harness, user.Id);
    }

    [Test]
    public async Task Revoked_when_recovery_codes_are_regenerated()
    {
        var harness = Harness();
        var (user, secret, deviceToken) = await TrustedAsync(harness);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.TwoFactor.RegenerateRecoveryCodesAsync(user.Id, harness.CurrentCode(secret));

        var result = await harness.SignInAsync("pianonic", Password, deviceToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await AssertNoLiveDeviceAsync(harness, user.Id);
    }

    /// <summary>
    /// The one the security stamp cannot carry: bumping it here would revoke the refresh family of
    /// the session being established, so redeeming a recovery code would sign the user out.
    /// </summary>
    [Test]
    public async Task Revoked_when_a_recovery_code_is_redeemed()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, codes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var trusted = await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true);

        var deviceToken = trusted.TrustedDevice!.Token;

        // Now lose the device and use a recovery code.
        var second = await harness.SignInAsync("pianonic", Password);
        var recovered = await harness.VerifyAsync(second.Challenge!.Token, codes[0]);

        // The sign-in itself must succeed - this is the check that would fail if we bumped the stamp.
        await Assert.That(recovered.Succeeded).IsTrue();
        await Assert.That(recovered.Tokens).IsNotNull();

        await AssertNoLiveDeviceAsync(harness, user.Id);

        var result = await harness.SignInAsync("pianonic", Password, deviceToken);
        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    [Test]
    public async Task A_recovery_code_never_issues_a_device_token()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (_, codes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        var recovered = await harness.VerifyAsync(started.Challenge!.Token, codes[0], rememberDevice: true);

        await Assert.That(recovered.Succeeded).IsTrue();
        await Assert.That(recovered.TrustedDevice).IsNull();
    }

    [Test]
    public async Task Revoked_when_refresh_token_reuse_is_detected()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password, deviceToken);
        var refreshToken = signedIn.Tokens!.RefreshToken;

        await harness.SignIn.RefreshAsync(refreshToken);
        var reused = await harness.SignIn.RefreshAsync(refreshToken);

        await Assert.That(reused.Outcome).IsEqualTo(SignInOutcome.RefreshTokenReused);
        await AssertNoLiveDeviceAsync(harness, user.Id);
    }

    [Test]
    public async Task Revoked_by_the_user()
    {
        var harness = Harness();
        var (user, _, deviceToken) = await TrustedAsync(harness);

        var devices = await harness.TrustedDevices.ListAsync(user.Id);
        await Assert.That(devices.Count).IsEqualTo(1);

        await Assert.That(await harness.TrustedDevices.RevokeAsync(user.Id, devices[0].Id)).IsTrue();

        var result = await harness.SignInAsync("pianonic", Password, deviceToken);
        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    [Test]
    public async Task Revoking_someone_elses_device_reports_the_same_as_one_that_never_existed()
    {
        var harness = Harness();
        var (user, _, _) = await TrustedAsync(harness);

        await Assert.That(await harness.TrustedDevices.RevokeAsync(user.Id, Guid.NewGuid())).IsFalse();
    }

    // ── The revocation that must NOT happen ──

    /// <summary>
    /// Signing out is not a security event, and a device surviving it is the entire feature. This is
    /// the one place where "revoke everything" reads correct and is wrong.
    /// </summary>
    [Test]
    public async Task Signing_out_leaves_the_trusted_device_alone()
    {
        var harness = Harness();
        var (_, _, deviceToken) = await TrustedAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password, deviceToken);
        await harness.SignIn.SignOutAsync(signedIn.Tokens!.RefreshToken);

        harness.Clock.Now = harness.Clock.Now.AddHours(1);
        var again = await harness.SignInAsync("pianonic", Password, signedIn.TrustedDevice!.Token);

        await Assert.That(again.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    // ── Lockout and enforcement ──

    [Test]
    public async Task A_locked_account_is_refused_despite_a_valid_device_token()
    {
        var harness = Harness();
        var (_, _, deviceToken) = await TrustedAsync(harness);

        for (var attempt = 0; attempt < harness.Options.MaxFailedAttempts; attempt++)
            await harness.SignInAsync("pianonic", "wrong password", deviceToken);

        var result = await harness.SignInAsync("pianonic", Password, deviceToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.LockedOut);
    }

    [Test]
    public async Task An_unenrolled_user_gains_nothing_from_any_device_token()
    {
        var harness = Harness(configureTwoFactor: options => options.Enforcement = TwoFactorEnforcement.RequiredForAll);
        var (_, _, deviceToken) = await TrustedAsync(harness);

        // A second account that never enrolled, presenting the first one's token.
        await harness.Accounts.RegisterAsync(new RegisterRequest("stranger", "stranger@example.com", Password));

        var result = await harness.SignInAsync("stranger", Password, deviceToken);

        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(harness.Issuer.Issued[^1].TwoFactorEnrolmentRequired).IsTrue();
        await Assert.That(harness.Issuer.Issued[^1].AuthenticationMethods).DoesNotContain("mfa");
    }

    // ── The cap ──

    [Test]
    public async Task The_oldest_family_is_revoked_when_the_limit_is_reached()
    {
        var harness = Harness(options => options.MaxDevicesPerUser = 2);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var tokens = new List<string>();

        for (var device = 0; device < 3; device++)
        {
            harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
            var started = await harness.SignInAsync("pianonic", Password);
            var finished = await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true);
            tokens.Add(finished.TrustedDevice!.Token);
        }

        var live = await harness.TrustedDevices.ListAsync(user.Id);
        await Assert.That(live.Count).IsEqualTo(2);

        // The first one out, the newest two kept.
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var oldest = await harness.SignInAsync("pianonic", Password, tokens[0]);
        await Assert.That(oldest.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    // ── Refresh carries the source ──

    [Test]
    public async Task A_refresh_keeps_the_source_and_the_original_second_factor_time()
    {
        var harness = Harness();
        var (_, _, deviceToken) = await TrustedAsync(harness);

        var liveAt = harness.Clock.Now;
        harness.Clock.Now = harness.Clock.Now.AddDays(1);

        var signedIn = await harness.SignInAsync("pianonic", Password, deviceToken);
        var refreshed = await harness.SignIn.RefreshAsync(signedIn.Tokens!.RefreshToken);

        await Assert.That(refreshed.Succeeded).IsTrue();

        var issued = harness.Issuer.Issued[^1];
        await Assert.That(issued.TwoFactorSource).IsEqualTo(TwoFactorSource.Device);
        await Assert.That(issued.SecondFactorAt).IsEqualTo(liveAt);
        await Assert.That(issued.AuthenticationMethods).DoesNotContain("otp");
    }

    // ── Not registered ──

    [Test]
    public async Task With_no_device_store_registered_a_device_token_is_simply_ignored()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true, withTrustedDevices: false);
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var result = await harness.SignInAsync("pianonic", Password, "some-token-from-somewhere");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
    }

    private static async Task AssertNoLiveDeviceAsync(PasswordHarness harness, Guid userId)
    {
        var live = harness.Devices.Devices
            .Count(device => device.UserId == userId && device.RevokedAt is null && device.RotatedAt is null);

        await Assert.That(live).IsEqualTo(0);
    }
}
