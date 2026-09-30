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

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
    }

    [Test]
    public async Task A_reset_link_redeemed_in_parallel_sets_a_password_at_most_once()
    {
        var issued = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(issued)));

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        var token = issued.Single();

        var attempts = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(index =>
            app.Client.PostJson("/auth/password/reset", new { token, newPassword = $"a new password number {index}" })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.NoContent)).IsEqualTo(1);
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

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
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

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
    }

    /// <summary>
    /// The parallel test above sends one TOTP code ten times, and the recorded step refuses nine of
    /// them before the challenge is ever asked. Ten different recovery codes each pass on their own,
    /// so only the challenge's conditional spend can keep this to one session.
    /// </summary>
    [Test]
    public async Task A_challenge_answered_with_different_recovery_codes_in_parallel_signs_in_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var codes = await account.EnrolForRecoveryCodesAsync();

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");

        var attempts = await Task.WhenAll(codes.Select(code =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
    }

    /// <summary>
    /// A recovery code in one tab and a TOTP code in another, on the same challenge. The recovery
    /// code used to be spent before the challenge, so the tab that lost the challenge had burned a
    /// code and got no session for it.
    /// </summary>
    [Test]
    public async Task A_recovery_code_that_loses_its_challenge_is_not_spent()
    {
        var challenges = new HoldFirstConsume();
        await using var app = await TestApp.StartAsync(configureServices: challenges.Register);

        var account = await Account.RegisterAsync(app);
        var recoveryCode = (await account.EnrolForRecoveryCodesAsync())[0];
        var secret = account.Secret!;
        var userId = Guid.Parse(account.Claims().String("sub")!);

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");

        // The recovery-code tab reaches the challenge first and is held there.
        challenges.Hold = true;
        var withRecovery = app.RawClient.PostJson("/auth/2fa/verify", new { challenge, code = recoveryCode });
        await challenges.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        // The other tab finishes in the meantime.
        app.Time.AdvanceToNextTotpStep();
        var withTotp = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(secret, app.Time.Now) });
        await Assert.That(withTotp.StatusCode).IsEqualTo(HttpStatusCode.OK);

        challenges.Let();
        await Assert.That((await withRecovery).StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        await using var scope = app.Services.CreateAsyncScope();
        var unused = await scope.ServiceProvider.GetRequiredService<IRecoveryCodeStore>().CountUnusedAsync(userId);

        await Assert.That(unused).IsEqualTo(10);
    }

    /// <summary>
    /// A double-click: the losing request reserved its attempt after the winner had cleared the
    /// count, lost the challenge, and was then counted as a wrong code - one stray failure left on
    /// an account that had just signed in.
    /// </summary>
    [Test]
    public async Task A_right_code_that_loses_its_challenge_leaves_no_failure_behind()
    {
        var credentials = new HoldFirstCredentialRead();
        await using var app = await TestApp.StartAsync(configureServices: credentials.Register);

        var account = await Account.RegisterAsync(app);
        var recoveryCode = (await account.EnrolForRecoveryCodesAsync())[0];
        var secret = account.Secret!;
        var userId = Guid.Parse(account.Claims().String("sub")!);

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");

        // Past the challenge checks, not yet counted.
        credentials.Hold = true;
        var loser = app.RawClient.PostJson("/auth/2fa/verify", new { challenge, code = recoveryCode });
        await credentials.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        app.Time.AdvanceToNextTotpStep();
        var winner = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(secret, app.Time.Now) });
        await Assert.That(winner.StatusCode).IsEqualTo(HttpStatusCode.OK);

        credentials.Let();
        await Assert.That((await loser).StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        await using var scope = app.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>().FindByUserIdAsync(userId);

        await Assert.That(stored!.FailedAttemptCount).IsEqualTo(0);
    }

    /// <summary>A real store, except that the first call a subclass routes through <see cref="Wait"/>
    /// after <see cref="Hold"/> is set waits until the test lets it go.</summary>
    private abstract class HoldFirst
    {
        private readonly ManualResetEventSlim _release = new();
        private int _held;

        internal volatile bool Hold;

        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal abstract void Register(IServiceCollection services);

        internal void Let()
        {
            Hold = false;
            _release.Set();
        }

        protected void Wait()
        {
            if (!Hold || Interlocked.Exchange(ref _held, 1) == 1)
                return;

            Entered.TrySetResult();
            _release.Wait(TimeSpan.FromSeconds(30));
        }
    }

    /// <summary>The real credential store, except that the first read by user id after
    /// <see cref="HoldFirst.Hold"/> is set waits until the test lets it go.</summary>
    private sealed class HoldFirstCredentialRead : HoldFirst
    {
        internal override void Register(IServiceCollection services) =>
            services.Decorate<IPasswordCredentialStore>(inner => new Held(this, inner));

        private sealed class Held(HoldFirstCredentialRead owner, IPasswordCredentialStore inner) : IPasswordCredentialStore
        {
            public Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
            {
                owner.Wait();
                return inner.FindByUserIdAsync(userId, cancellationToken);
            }

            public Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default) =>
                inner.FindByIdentifierAsync(normalizedIdentifier, cancellationToken);

            public Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
                inner.FindByNormalizedEmailAsync(normalizedEmail, cancellationToken);

            public Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
                inner.CreateAsync(credential, cancellationToken);

            public Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
                inner.UpdateAsync(credential, cancellationToken);
        }
    }

    /// <summary>The real challenge store, except that the first spend after
    /// <see cref="HoldFirst.Hold"/> is set waits until the test lets it go.</summary>
    private sealed class HoldFirstConsume : HoldFirst
    {
        internal override void Register(IServiceCollection services) =>
            services.Decorate<ITwoFactorChallengeStore>(inner => new Held(this, inner));

        private sealed class Held(HoldFirstConsume owner, ITwoFactorChallengeStore inner) : ITwoFactorChallengeStore
        {
            public Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default) =>
                inner.CreateAsync(challenge, cancellationToken);

            public Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
                inner.FindByHashAsync(tokenHash, cancellationToken);

            public Task<bool> MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
            {
                owner.Wait();
                return inner.MarkConsumedAsync(challengeId, consumedAt, cancellationToken);
            }

            public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
                inner.DeleteExpiredAsync(expiredBefore, cancellationToken);
        }
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

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.NoContent)).IsEqualTo(1);
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
        var recoveryCode = (await account.EnrolForRecoveryCodesAsync())[0];

        var challenges = new List<string>();
        for (var i = 0; i < Parallel; i++)
            challenges.Add((await (await account.LoginAsync()).Json()).String("challenge")!);

        var attempts = await Task.WhenAll(challenges.Select(challenge =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code = recoveryCode })));

        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsEqualTo(1);
    }
}
