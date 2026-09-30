using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class ConcurrentRefreshHttpTests
{
    [Test]
    public async Task A_refresh_token_presented_in_parallel_is_exchanged_at_most_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var signedIn = await (await account.LoginAsync()).Json();
        var refreshToken = signedIn.String("refresh_token");

        var attempts = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            app.Client.PostJson("/auth/refresh", new { refreshToken })));

        // At most one, not exactly one: a loser's reuse revokes the family the winner's new token
        // belongs to, so none at all is a right answer.
        await Assert.That(attempts.Count(response => response.StatusCode == HttpStatusCode.OK)).IsLessThanOrEqualTo(1);
    }

    /// <summary>Held before the new token is written, so the sign-out revokes a family that does not
    /// yet include it.</summary>
    [Test]
    public async Task A_sign_out_during_a_refresh_leaves_no_live_token()
    {
        var store = new HeldRefreshTokenStore();
        await using var app = await TestApp.StartAsync(configureServices: store.Register);

        var account = await Account.RegisterAsync(app);
        var refreshToken = (await (await account.LoginAsync()).Json()).String("refresh_token");

        store.HoldCreate = true;
        var refresh = app.Client.PostJson("/auth/refresh", new { refreshToken });
        await store.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await app.Client.PostJson("/auth/logout", new { refreshToken });
        store.Let();

        var refreshed = await refresh;
        await Assert.That(refreshed.StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        await using var scope = app.Services.CreateAsyncScope();
        var live = await scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>().FindLiveByFamilyAsync(store.FamilyId);
        await Assert.That(live).IsNull();
    }

    /// <summary>Held between the read and the rotate write, so the sign-out makes the write lose without
    /// any reuse having happened.</summary>
    [Test]
    public async Task A_refresh_that_loses_to_a_sign_out_is_not_answered_as_reuse()
    {
        var store = new HeldRefreshTokenStore();
        await using var app = await TestApp.StartAsync(configureServices: store.Register);

        var account = await Account.RegisterAsync(app);
        var refreshToken = (await (await account.LoginAsync()).Json()).String("refresh_token");

        using var reuse = new InstrumentProbe(app, "toamaisutaa.refresh_token.reuse_detections");

        store.HoldRotate = true;
        var refresh = app.Client.PostJson("/auth/refresh", new { refreshToken });
        await store.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await app.Client.PostJson("/auth/logout", new { refreshToken });
        store.Let();

        await Assert.That((await refresh).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(reuse.Total).IsEqualTo(0);
    }

    private sealed class HeldRefreshTokenStore
    {
        private readonly ManualResetEventSlim _release = new();

        internal volatile bool HoldCreate;
        internal volatile bool HoldRotate;

        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Guid FamilyId { get; private set; }

        internal void Register(IServiceCollection services) =>
            services.Decorate<IRefreshTokenStore>(inner => new Held(this, inner));

        internal void Let()
        {
            HoldCreate = false;
            HoldRotate = false;
            _release.Set();
        }

        private void Wait(bool hold, Guid familyId)
        {
            if (!hold)
                return;

            FamilyId = familyId;
            Entered.TrySetResult();
            _release.Wait(TimeSpan.FromSeconds(30));
        }

        private sealed class Held(HeldRefreshTokenStore owner, IRefreshTokenStore inner) : IRefreshTokenStore
        {
            public Task<ToamaisutaaRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
                inner.FindByHashAsync(tokenHash, cancellationToken);

            public Task CreateAsync(ToamaisutaaRefreshToken token, CancellationToken cancellationToken = default)
            {
                owner.Wait(owner.HoldCreate, token.FamilyId);
                return inner.CreateAsync(token, cancellationToken);
            }

            public async Task<bool> MarkRotatedAsync(Guid tokenId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default)
            {
                owner.Wait(owner.HoldRotate, Guid.Empty);
                return await inner.MarkRotatedAsync(tokenId, rotatedAt, cancellationToken);
            }

            public Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
                inner.RevokeFamilyAsync(familyId, reason, revokedAt, cancellationToken);

            public Task RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
                inner.RevokeAllForUserAsync(userId, reason, revokedAt, cancellationToken);

            public Task<ToamaisutaaRefreshToken?> FindLiveByFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
                inner.FindLiveByFamilyAsync(familyId, cancellationToken);

            public Task<IReadOnlyList<ToamaisutaaRefreshToken>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.ListActiveAsync(userId, cancellationToken);

            public Task<bool> UpdateSecondFactorAsync(
                Guid familyId,
                string authenticationMethods,
                string twoFactorSource,
                DateTimeOffset secondFactorAt,
                CancellationToken cancellationToken = default) =>
                inner.UpdateSecondFactorAsync(familyId, authenticationMethods, twoFactorSource, secondFactorAt, cancellationToken);

            public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
                inner.DeleteExpiredAsync(expiredBefore, cancellationToken);
        }
    }
}
