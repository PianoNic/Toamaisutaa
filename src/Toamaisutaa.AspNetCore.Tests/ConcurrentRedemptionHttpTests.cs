using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Single-use tokens presented in parallel. Each was checked for "not spent yet" and then marked
/// spent in a second step, so every request that landed between the two was let through.
/// </summary>
public class ConcurrentRedemptionHttpTests
{
    private const int Parallel = 10;

    [Test]
    public async Task A_magic_link_redeemed_in_parallel_signs_in_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        var token = await account.RequestMagicLinkAsync();

        var attempts = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(_ =>
            app.Client.PostJson("/auth/magic-link/verify", new { token })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }

    [Test]
    public async Task A_reset_link_redeemed_in_parallel_sets_a_password_at_most_once()
    {
        var issued = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new ResetCapture(issued)));

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        var token = issued.Single();

        var attempts = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(index =>
            app.Client.PostJson("/auth/password/reset", new { token, newPassword = $"a new password number {index}" })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.NoContent)).IsLessThanOrEqualTo(1);
    }

    [Test]
    public async Task A_two_factor_challenge_answered_in_parallel_signs_in_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");
        app.Time.AdvanceToNextTotpStep();
        var code = Totp.Code(account.Secret!, app.Time.Now);

        var attempts = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(_ =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }

    /// <summary>
    /// One TOTP code, typed into several sign-ins at once. The challenges are separate, so the only
    /// thing that makes a code single-use is the recorded step - and that was read, compared, then
    /// written, with every request in between let through.
    /// </summary>
    [Test]
    public async Task A_totp_code_used_in_parallel_signs_in_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenges = new List<string>();
        for (var i = 0; i < Parallel; i++)
            challenges.Add((await (await account.LoginAsync()).Json()).String("challenge")!);

        app.Time.AdvanceToNextTotpStep();
        var code = Totp.Code(account.Secret!, app.Time.Now);

        var attempts = await Task.WhenAll(challenges.Select(challenge =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }

    [Test]
    public async Task A_verification_link_redeemed_in_parallel_is_accepted_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        var token = app.IssuedEmailVerifications[^1].Token;

        var attempts = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(_ =>
            app.Client.PostJson("/auth/email/verify", new { token })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.NoContent)).IsLessThanOrEqualTo(1);
    }

    /// <summary>
    /// One recovery code, typed into several sign-ins at once. Each challenge is separate, so only
    /// the code's own spend stands between it and a session per challenge.
    /// </summary>
    [Test]
    public async Task A_recovery_code_used_in_parallel_signs_in_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await (await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(secret, app.Time.Now) },
            account.AccessToken)).Json();

        var recoveryCode = confirm.Strings("recoveryCodes")[0];

        var challenges = new List<string>();
        for (var i = 0; i < Parallel; i++)
            challenges.Add((await (await account.LoginAsync()).Json()).String("challenge")!);

        var attempts = await Task.WhenAll(challenges.Select(challenge =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code = recoveryCode })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }

    private sealed class ResetCapture(List<string> issued) : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
        {
            issued.Add(resetToken);
            return Task.CompletedTask;
        }
    }
}
