using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class TwoFactorTests
{
    private static PasswordHarness Harness(Action<ToamaisutaaTwoFactorOptions>? configure = null) =>
        PasswordHarness.Create(configureTwoFactor: configure, withTwoFactor: true);

    // ── Enrolment ──

    /// <summary>
    /// The whole reason enrolment is two steps. If generating a secret switched the second factor
    /// on, anyone who opened the settings page and closed it would be locked out of their account.
    /// </summary>
    [Test]
    public async Task Beginning_an_enrolment_changes_nothing_about_signing_in()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        await harness.TwoFactor.BeginEnrolmentAsync(user.Id);

        var status = await harness.TwoFactor.GetStatusAsync(user.Id);
        await Assert.That(status.Enabled).IsFalse();
        await Assert.That(status.EnrolmentPending).IsTrue();

        var result = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(result.Tokens).IsNotNull();
    }

    [Test]
    public async Task Confirming_with_a_working_code_enables_it_and_returns_the_recovery_codes()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        var (_, codes) = await harness.EnrolAsync(user.Id);

        await Assert.That(codes.Count).IsEqualTo(10);
        await Assert.That(codes.Distinct().Count()).IsEqualTo(10);

        var status = await harness.TwoFactor.GetStatusAsync(user.Id);
        await Assert.That(status.Enabled).IsTrue();
        await Assert.That(status.RecoveryCodesRemaining).IsEqualTo(10);
    }

    [Test]
    public async Task Confirming_with_a_wrong_code_leaves_it_off()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        await harness.TwoFactor.BeginEnrolmentAsync(user.Id);

        await Assert.That(async () => await harness.TwoFactor.ConfirmEnrolmentAsync(user.Id, "000000"))
            .Throws<TwoFactorEnrolmentException>();

        await Assert.That((await harness.TwoFactor.GetStatusAsync(user.Id)).Enabled).IsFalse();
    }

    /// <summary>
    /// A second call replaces the secret, which is right, and leaves anyone who scanned the first QR
    /// code holding a dead one. We cannot prove that is what happened - the old secret is gone - but
    /// the row having been rewritten is enough to say so.
    /// </summary>
    [Test]
    public async Task A_second_enrolment_supersedes_the_first_and_says_so_when_confirmation_fails()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        var first = await harness.TwoFactor.BeginEnrolmentAsync(user.Id);

        if (!Base32.TryDecode(first.Secret, out var firstSecret))
            throw new InvalidOperationException("The enrolment secret is not valid base32.");

        harness.Clock.Now = harness.Clock.Now.AddMinutes(1);
        await harness.TwoFactor.BeginEnrolmentAsync(user.Id);

        var exception = await Assert.ThrowsAsync<TwoFactorEnrolmentException>(
            async () => await harness.TwoFactor.ConfirmEnrolmentAsync(user.Id, harness.CurrentCode(firstSecret)));

        await Assert.That(exception.Message).Contains("earlier QR code");
    }

    [Test]
    public async Task Enrolling_again_once_it_is_confirmed_is_refused()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        await harness.EnrolAsync(user.Id);

        await Assert.That(async () => await harness.TwoFactor.BeginEnrolmentAsync(user.Id))
            .Throws<TwoFactorEnrolmentException>();
    }

    // ── Sign-in ──

    [Test]
    public async Task An_enrolled_user_gets_a_challenge_instead_of_tokens()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var result = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.TwoFactorRequired);
        await Assert.That(result.Tokens).IsNull();
        await Assert.That(result.Challenge).IsNotNull();
    }

    [Test]
    public async Task The_challenge_and_a_code_complete_the_sign_in_with_an_mfa_amr()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        // A step forward, because confirming the enrolment already spent the current one.
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);

        var finished = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        await Assert.That(finished.Succeeded).IsTrue();
        await Assert.That(finished.Tokens).IsNotNull();

        var issued = harness.Issuer.Issued[^1];
        await Assert.That(issued.AuthenticationMethods).IsEquivalentTo(new[] { "pwd", "otp", "mfa" });
    }

    [Test]
    public async Task A_challenge_cannot_be_used_twice()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var again = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge.Token, harness.CurrentCode(secret));

        await Assert.That(again.Outcome).IsEqualTo(SignInOutcome.ChallengeAlreadyUsed);
    }

    [Test]
    public async Task A_challenge_expires()
    {
        var harness = Harness(options => options.ChallengeLifetime = TimeSpan.FromMinutes(5));
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        harness.Clock.Now = harness.Clock.Now.AddMinutes(6);

        var result = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.ChallengeExpired);
    }

    /// <summary>
    /// Disabling needs proof, so nobody can do this to somebody else - but the account holder can do
    /// it from a second device while a challenge sits unspent on the first. Checking that the
    /// challenge is unconsumed is not enough; the thing it was challenging has to still exist.
    /// </summary>
    [Test]
    public async Task A_challenge_does_not_outlive_the_enrolment_it_was_issued_against()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var disabled = await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));
        await Assert.That(disabled.Succeeded).IsTrue();

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var result = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidChallenge);
    }

    [Test]
    public async Task An_unknown_challenge_is_refused()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var result = await harness.SignIn.VerifyTwoFactorAsync("not-a-challenge", "000000");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidChallenge);
    }

    // ── Recovery codes ──

    [Test]
    public async Task A_recovery_code_completes_a_sign_in_once_and_never_again()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (_, codes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var finished = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, codes[0]);

        await Assert.That(finished.Succeeded).IsTrue();

        // A recovery code says the person proved a second factor, but not that an authenticator
        // was involved - so no otp.
        await Assert.That(harness.Issuer.Issued[^1].AuthenticationMethods).IsEquivalentTo(new[] { "pwd", "mfa" });

        var second = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var reused = await harness.SignIn.VerifyTwoFactorAsync(second.Challenge!.Token, codes[0]);

        await Assert.That(reused.Outcome).IsEqualTo(SignInOutcome.InvalidTwoFactorCode);
    }

    [Test]
    public async Task Hyphens_and_case_do_not_matter_when_a_recovery_code_is_typed_back()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (_, codes) = await harness.EnrolAsync(user.Id);

        var typed = codes[0].Replace("-", string.Empty).ToLowerInvariant();

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var finished = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, typed);

        await Assert.That(finished.Succeeded).IsTrue();
    }

    [Test]
    public async Task Spending_down_to_the_low_water_mark_says_so()
    {
        var harness = Harness(options =>
        {
            options.RecoveryCodeCount = 4;
            options.RecoveryCodeLowWaterMark = 3;
        });

        var user = await harness.RegisterAsync();
        var (_, codes) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var finished = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, codes[0]);

        await Assert.That(finished.Succeeded).IsTrue();
        await Assert.That(finished.RecoveryCodesRunningLow).IsTrue();
    }

    [Test]
    public async Task Regenerating_kills_every_previous_code()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, oldCodes) = await harness.EnrolAsync(user.Id);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var regenerated = await harness.TwoFactor.RegenerateRecoveryCodesAsync(user.Id, harness.CurrentCode(secret));

        await Assert.That(regenerated.RecoveryCodes.Intersect(oldCodes).Any()).IsFalse();

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var result = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, oldCodes[0]);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidTwoFactorCode);
    }

    // ── Disabling ──

    [Test]
    public async Task Disabling_needs_proof()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        await harness.EnrolAsync(user.Id);

        var result = await harness.TwoFactor.DisableAsync(user.Id, "000000");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That((await harness.TwoFactor.GetStatusAsync(user.Id)).Enabled).IsTrue();
    }

    [Test]
    public async Task Disabling_takes_the_recovery_codes_with_it()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));

        await Assert.That(harness.TwoFactorStore.Codes.Count(code => code.UserId == user.Id)).IsEqualTo(0);

        var result = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    // ── The security stamp ──

    [Test]
    [Arguments("enable")]
    [Arguments("disable")]
    [Arguments("regenerate")]
    public async Task Every_two_factor_operation_moves_the_security_stamp(string operation)
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        var before = user.SecurityStamp;

        var (secret, _) = await harness.EnrolAsync(user.Id);

        if (operation != "enable")
        {
            harness.Clock.Now = harness.Clock.Now.AddSeconds(30);

            if (operation == "disable")
                await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));
            else
                await harness.TwoFactor.RegenerateRecoveryCodesAsync(user.Id, harness.CurrentCode(secret));
        }

        await Assert.That(harness.Users.Users.Single(entry => entry.Id == user.Id).SecurityStamp).IsNotEqualTo(before);
    }

    [Test]
    public async Task A_refresh_chain_minted_before_the_stamp_moved_is_refused_and_its_family_revoked()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();

        var signedIn = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");
        var refreshToken = signedIn.Tokens!.RefreshToken;

        // Enrolling is one of the six operations that ends outstanding sessions.
        await harness.EnrolAsync(user.Id);

        // Put this one token back: enrolment revoked the family, and the stamp check is what this
        // test is about rather than the revocation that happens to also cover it.
        var stored = harness.Passwords.RefreshTokens.Single(token => token.TokenHash == SecureTokens.HashToken(refreshToken));
        stored.RevokedAt = null;
        stored.RevokedReason = null;

        var result = await harness.SignIn.RefreshAsync(refreshToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.SecurityStampChanged);
        await Assert.That(harness.Passwords.RefreshTokens.Single(token => token.Id == stored.Id).RevokedAt).IsNotNull();
    }

    [Test]
    public async Task A_refresh_carries_the_methods_the_session_was_established_with()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        var finished = await harness.SignIn.VerifyTwoFactorAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        var refreshed = await harness.SignIn.RefreshAsync(finished.Tokens!.RefreshToken);

        await Assert.That(refreshed.Succeeded).IsTrue();
        await Assert.That(harness.Issuer.Issued[^1].AuthenticationMethods).IsEquivalentTo(new[] { "pwd", "otp", "mfa" });
    }

    // ── Encryption at rest ──

    [Test]
    public async Task The_secret_is_not_stored_in_the_clear()
    {
        var harness = Harness();
        var user = await harness.RegisterAsync();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var stored = harness.TwoFactorStore.Enrolments.Single(enrolment => enrolment.UserId == user.Id);

        await Assert.That(stored.SecretCiphertext).IsNotEquivalentTo(secret);
        await Assert.That(stored.SecretNonce.Length).IsGreaterThan(0);
        await Assert.That(stored.SecretTag.Length).IsGreaterThan(0);
    }

    [Test]
    public async Task A_retired_key_still_decrypts_and_the_row_is_rewritten_under_the_current_one()
    {
        var oldKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var newKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var options = new ToamaisutaaTwoFactorOptions { EncryptionKey = oldKey, EncryptionKeyVersion = "1" };
        var protector = new AesGcmSecretProtector(Options.Create(options));

        var secret = RandomNumberGenerator.GetBytes(20);
        var wrapped = protector.Protect(secret);

        var rotated = new ToamaisutaaTwoFactorOptions
        {
            EncryptionKey = newKey,
            EncryptionKeyVersion = "2",
            RetiredEncryptionKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["1"] = oldKey },
        };

        var after = new AesGcmSecretProtector(Options.Create(rotated));

        await Assert.That(after.Unprotect(wrapped)).IsEquivalentTo(secret);
        await Assert.That(after.NeedsRewrap("1")).IsTrue();
        await Assert.That(after.NeedsRewrap("2")).IsFalse();
    }

    /// <summary>
    /// The pepper had this bug: a retired entry keyed to the active version shadowed the active key
    /// and every stored value stopped verifying. Same shape, so the same test.
    /// </summary>
    [Test]
    public async Task A_missing_key_fails_closed_rather_than_guessing()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var protector = new AesGcmSecretProtector(Options.Create(
            new ToamaisutaaTwoFactorOptions { EncryptionKey = key, EncryptionKeyVersion = "1" }));

        var wrapped = protector.Protect(RandomNumberGenerator.GetBytes(20));

        var without = new AesGcmSecretProtector(Options.Create(
            new ToamaisutaaTwoFactorOptions { EncryptionKey = key, EncryptionKeyVersion = "2" }));

        await Assert.That(() => without.Unprotect(wrapped)).Throws<InvalidOperationException>();
    }

    // ── Not registered at all ──

    [Test]
    public async Task Password_login_with_no_second_factor_registered_is_untouched()
    {
        var harness = PasswordHarness.Create(withTwoFactor: false);
        await harness.RegisterAsync();

        var result = await harness.SignIn.SignInAsync("pianonic", "correct horse battery");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(harness.Issuer.Issued[^1].AuthenticationMethods).IsEquivalentTo(new[] { "pwd" });
    }
}
