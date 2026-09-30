using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class SignInResetRaceHttpTests
{
    [Test]
    public async Task A_session_won_with_the_old_password_does_not_survive_the_reset()
    {
        var (app, hasher, resets) = await StartAsync();
        await using var _ = app;

        var account = await Account.RegisterAsync(app);
        hasher.Hold = account.Password;

        var signIn = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await ResetAsync(app, account, resets);
        hasher.Let();

        var won = await signIn;
        var refreshToken = (await won.Json()).String("refresh_token");

        // Otherwise a refused sign-in posts a null token and gets the same 401 for another reason.
        await Assert.That(won.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(refreshToken).IsNotNull();

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken });

        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_challenge_won_with_the_old_password_cannot_be_finished_after_the_reset()
    {
        var (app, hasher, resets) = await StartAsync();
        await using var _ = app;

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        hasher.Hold = account.Password;

        var signIn = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await ResetAsync(app, account, resets);
        hasher.Let();

        var challenge = (await (await signIn).Json()).String("challenge");

        // Otherwise a refused sign-in posts a null challenge and gets the same 401 for another reason.
        await Assert.That(challenge).IsNotNull();

        app.Time.AdvanceToNextTotpStep();
        var verified = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verified.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// EF's identity map makes the challenge reuse the pre-hash user read, so only a store that reads
    /// afresh proves the stamp is passed along rather than right by accident.
    /// </summary>
    [Test]
    public async Task A_challenge_carries_the_stamp_read_before_the_hash_whatever_the_store_caches()
    {
        var (app, hasher, resets) = await StartAsync(freshUserReads: true);
        await using var _ = app;

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        hasher.Hold = account.Password;

        var signIn = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await ResetAsync(app, account, resets);
        hasher.Let();

        var challenge = (await (await signIn).Json()).String("challenge");

        // Otherwise a refused sign-in posts a null challenge and gets the same 401 for another reason.
        await Assert.That(challenge).IsNotNull();

        app.Time.AdvanceToNextTotpStep();
        var verified = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verified.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    private static async Task<(TestApp App, HeldHasher Hasher, List<string> Resets)> StartAsync(bool freshUserReads = false)
    {
        var hasher = new HeldHasher();
        var resets = new List<string>();

        var app = await TestApp.StartAsync(configureServices: services =>
        {
            hasher.Register(services);
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets));

            if (freshUserReads)
            {
                var real = services.Last(descriptor => descriptor.ServiceType == typeof(IUserStore)).ImplementationFactory!;
                services.AddScoped<IUserStore>(provider =>
                    new FreshReads((IUserStore)real(provider), provider.GetRequiredService<IServiceScopeFactory>(), real));
            }
        });

        return (app, hasher, resets);
    }

    private sealed class FreshReads(IUserStore inner, IServiceScopeFactory scopes, Func<IServiceProvider, object> real) : IUserStore
    {
        public async Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            await using var scope = scopes.CreateAsyncScope();
            return await ((IUserStore)real(scope.ServiceProvider)).FindByIdAsync(id, cancellationToken);
        }

        public Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            inner.FindByEmailAsync(email, cancellationToken);

        public Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(profile, cancellationToken);

        public Task<ToamaisutaaUser> CreateAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(user, cancellationToken);

        public Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default) =>
            inner.UpdateProfileAsync(user, profile, cancellationToken);

        public Task UpdateSecurityStampAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default) =>
            inner.UpdateSecurityStampAsync(userId, securityStamp, cancellationToken);

        public Task SetUserNameAsync(Guid userId, string userName, CancellationToken cancellationToken = default) =>
            inner.SetUserNameAsync(userId, userName, cancellationToken);

        public Task SetEmailAsync(Guid userId, string email, CancellationToken cancellationToken = default) =>
            inner.SetEmailAsync(userId, email, cancellationToken);

        public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(userId, cancellationToken);
    }

    private static async Task ResetAsync(TestApp app, Account account, List<string> resets)
    {
        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });

        var reset = await app.Client.PostJson("/auth/password/reset", new { token = resets[^1], newPassword = "the password after the reset" });

        if (reset.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Reset failed: {reset.StatusCode}");
    }
}
