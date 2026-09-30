using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Instrument names and tag values are spelled out as literals so that a rename a dashboard query
/// would not survive breaks a test.
/// </summary>
public class MetricsTests
{
    private const string Password = "correct horse battery";

    private const string SignIns = "toamaisutaa.sign_in.attempts";
    private const string Lockouts = "toamaisutaa.lockouts";
    private const string TwoFactorVerifications = "toamaisutaa.two_factor.verifications";
    private const string ReuseDetections = "toamaisutaa.refresh_token.reuse_detections";
    private const string PasswordDuration = "toamaisutaa.password.verification.duration";

    [Test]
    public async Task ASuccessfulSignInIsCountedWithTheMethodsItProved()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("pianonic", Password);

        var measurement = probe.For(SignIns).Single();

        await Assert.That(measurement.Value).IsEqualTo(1);
        await Assert.That(measurement.Tag("result")).IsEqualTo("succeeded");
        await Assert.That(measurement.Tag("amr")).IsEqualTo("pwd");
    }

    [Test]
    public async Task AWrongPasswordIsCountedAsARefusalThatProvedNothing()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("pianonic", "wrong password entirely");

        var measurement = probe.For(SignIns).Single();

        await Assert.That(measurement.Tag("result")).IsEqualTo("invalid_grant");
        await Assert.That(measurement.Tag("amr")).IsEqualTo("none");
    }

    /// <summary>
    /// A result of its own would tell whoever reads the series which guesses named real accounts.
    /// </summary>
    [Test]
    public async Task AnUnknownIdentifierIsCountedAsTheSameRefusalAsAWrongPassword()
    {
        var harness = PasswordHarness.Create();

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("nobody", Password);

        await Assert.That(probe.For(SignIns).Single().Tag("result")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task CrossingTheLockoutThresholdIsCountedOnceAndNotAgainWhileLocked()
    {
        var harness = PasswordHarness.Create(options => options.MaxFailedAttempts = 3);
        await harness.RegisterAsync();

        using var probe = new MeterProbe(harness.Metrics.Meter);

        for (var attempt = 0; attempt < 5; attempt++)
            await harness.SignInAsync("pianonic", "wrong password entirely");

        await Assert.That(probe.For(Lockouts).Count).IsEqualTo(1);
    }

    [Test]
    public async Task CrossingTheThresholdWithWrongStepUpCodesIsCountedToo()
    {
        var harness = PasswordHarness.Create(options => options.MaxFailedAttempts = 2, withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        var sessionId = harness.Issuer.Issued[^1].SessionId!.Value;

        using var probe = new MeterProbe(harness.Metrics.Meter);

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

        await Assert.That(probe.For(Lockouts).Count).IsEqualTo(1);
    }

    [Test]
    public async Task AWorkingCodeIsCountedAgainstTheOtpSource()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);

        // Past the step the enrolment itself spent, or replay protection refuses the same code.
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        var measurement = probe.For(TwoFactorVerifications).Single();

        await Assert.That(measurement.Tag("source")).IsEqualTo("otp");
        await Assert.That(measurement.Tag("result")).IsEqualTo("succeeded");
    }

    [Test]
    public async Task AWrongCodeIsCountedAgainstTheSameSource()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.VerifyAsync(started.Challenge!.Token, "000000");

        var measurement = probe.For(TwoFactorVerifications).Single();

        await Assert.That(measurement.Tag("source")).IsEqualTo("otp");
        await Assert.That(measurement.Tag("result")).IsEqualTo("failed");
    }

    [Test]
    public async Task ARecoveryCodeIsCountedAgainstItsOwnSource()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await harness.RegisterAsync();
        var (_, recoveryCodes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.VerifyAsync(started.Challenge!.Token, recoveryCodes[0]);

        var measurement = probe.For(TwoFactorVerifications).Single();

        await Assert.That(measurement.Tag("source")).IsEqualTo("recovery");
        await Assert.That(measurement.Tag("result")).IsEqualTo("succeeded");
    }

    [Test]
    public async Task ATrustedDeviceStandingInForTheSecondFactorIsCountedAsOne()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true, withTrustedDevices: true);
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);

        var finished = await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret), rememberDevice: true);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("pianonic", Password, finished.TrustedDevice!.Token);

        var device = probe.For(TwoFactorVerifications).Single();

        await Assert.That(device.Tag("source")).IsEqualTo("device");
        await Assert.That(device.Tag("result")).IsEqualTo("succeeded");
        await Assert.That(probe.For(SignIns).Single().Tag("amr")).IsEqualTo("pwd mfa");
    }

    [Test]
    public async Task NoDeviceTokenIsNotAFailedDeviceVerification()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true, withTrustedDevices: true);
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("pianonic", Password);

        await Assert.That(probe.For(TwoFactorVerifications)).IsEmpty();
        await Assert.That(probe.For(SignIns).Single().Tag("result")).IsEqualTo("two_factor_required");
    }

    [Test]
    public async Task PresentingARotatedRefreshTokenIsCounted()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var first = (await harness.SignInAsync("pianonic", Password)).Tokens!;
        await harness.SignIn.RefreshAsync(first.RefreshToken);

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignIn.RefreshAsync(first.RefreshToken);

        await Assert.That(probe.For(ReuseDetections).Count).IsEqualTo(1);
    }

    [Test]
    public async Task ARefreshIsNotCountedAsASignInAttempt()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var first = (await harness.SignInAsync("pianonic", Password)).Tokens!;

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignIn.RefreshAsync(first.RefreshToken);

        await Assert.That(probe.For(SignIns)).IsEmpty();
    }

    [Test]
    public async Task AVerifiedPasswordIsTimed()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("pianonic", Password);

        var measurement = probe.For(PasswordDuration).Single();

        await Assert.That(measurement.Tag("result")).IsEqualTo("succeeded");
        await Assert.That(measurement.Value).IsGreaterThan(0);
    }

    /// <summary>
    /// The equalising derivation exists to cost what a real one costs, and this series is what would
    /// show it had stopped.
    /// </summary>
    [Test]
    public async Task TheDerivationForAnUnknownIdentifierIsTimedAsWell()
    {
        var harness = PasswordHarness.Create();

        using var probe = new MeterProbe(harness.Metrics.Meter);
        await harness.SignInAsync("nobody", Password);

        var measurement = probe.For(PasswordDuration).Single();

        await Assert.That(measurement.Tag("result")).IsEqualTo("no_credential");
        await Assert.That(measurement.Value).IsGreaterThan(0);
    }

    [Test]
    public async Task TheMeterIsNamedToamaisutaa()
    {
        var harness = PasswordHarness.Create();

        await Assert.That(harness.Metrics.Meter.Name).IsEqualTo("Toamaisutaa");
        await Assert.That(harness.Metrics.Meter.Name).IsEqualTo(ToamaisutaaDefaults.MeterName);
    }
}
