using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class TrustedDeviceHttpTests
{
    [Test]
    public async Task Remembering_a_device_returns_a_token_alongside_the_pair()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var body = await account.SignInWithSecondFactorAsync(rememberDevice: true, deviceLabel: "Ada's laptop");

        await Assert.That(body.String("device_token")).IsNotNull();
        await Assert.That(body.Has("device_expires_in")).IsTrue();
    }

    [Test]
    public async Task A_device_trusted_sign_in_skips_the_challenge_and_returns_a_rotated_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var issued = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        var second = await (await account.LoginAsync(deviceToken: issued)).Json();

        await Assert.That(second.Has("two_factor_required")).IsFalse();
        await Assert.That(second.String("access_token")).IsNotNull();

        var rotated = second.String("device_token");
        await Assert.That(rotated).IsNotNull();
        await Assert.That(rotated).IsNotEqualTo(issued);
    }

    [Test]
    public async Task Replaying_a_rotated_device_token_revokes_the_family()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var issued = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;
        await account.LoginAsync(deviceToken: issued);

        var replayed = await (await account.LoginAsync(deviceToken: issued)).Json();

        await Assert.That(replayed.Has("two_factor_required")).IsTrue();

        var devices = await (await app.Client.Get("/auth/devices", account.AccessToken)).Json();
        await Assert.That(devices.GetArrayLength()).IsEqualTo(0);
    }

    [Test]
    public async Task A_device_token_presented_in_parallel_skips_the_second_factor_at_most_once()
    {
        var store = new MeetBeforeRotating();
        await using var app = await TestApp.StartAsync(configureServices: store.Register);

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var issued = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        // Both held at the write, past every check, which is where a real race puts them.
        store.Hold = true;
        var attempts = await Task.WhenAll(account.LoginAsync(deviceToken: issued), account.LoginAsync(deviceToken: issued));
        var bodies = await Task.WhenAll(attempts.Select(response => response.Json()));

        await Assert.That(bodies.Count(body => body.Has("access_token"))).IsEqualTo(1);
    }

    private sealed class MeetBeforeRotating
    {
        private readonly CountdownEvent _arrived = new(2);

        internal volatile bool Hold;

        internal void Register(IServiceCollection services) =>
            services.Decorate<ITrustedDeviceStore>(inner => new Held(this, inner));

        private void Meet()
        {
            if (!Hold)
                return;

            _arrived.Signal();
            _arrived.Wait(TimeSpan.FromSeconds(30));
        }

        private sealed class Held(MeetBeforeRotating owner, ITrustedDeviceStore inner) : ITrustedDeviceStore
        {
            public Task<ToamaisutaaTrustedDevice?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
                inner.FindByHashAsync(tokenHash, cancellationToken);

            public Task<IReadOnlyList<ToamaisutaaTrustedDevice>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.ListActiveAsync(userId, cancellationToken);

            public Task CreateAsync(ToamaisutaaTrustedDevice device, CancellationToken cancellationToken = default) =>
                inner.CreateAsync(device, cancellationToken);

            public Task<bool> MarkRotatedAsync(Guid deviceId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default)
            {
                owner.Meet();
                return inner.MarkRotatedAsync(deviceId, rotatedAt, cancellationToken);
            }

            public Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
                inner.RevokeFamilyAsync(familyId, reason, revokedAt, cancellationToken);

            public Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
                inner.RevokeAllForUserAsync(userId, reason, revokedAt, cancellationToken);

            public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
                inner.DeleteExpiredAsync(expiredBefore, cancellationToken);
        }
    }

    [Test]
    public async Task The_rotated_token_keeps_the_original_absolute_lifetime()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var first = await account.SignInWithSecondFactorAsync(rememberDevice: true);
        var issued = first.String("device_token")!;
        var originalExpiry = first.GetProperty("device_expires_in").GetInt32();

        app.Time.Advance(TimeSpan.FromMinutes(2));

        var second = await (await account.LoginAsync(deviceToken: issued)).Json();

        // Rotation must not restart the lifetime, or a device signed in from monthly would never expire.
        await Assert.That(second.GetProperty("device_expires_in").GetInt32()).IsLessThan(originalExpiry);
    }

    [Test]
    public async Task The_device_list_marks_the_caller_s_own_device()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var body = await account.SignInWithSecondFactorAsync(rememberDevice: true, deviceLabel: "Ada's laptop");
        var deviceToken = body.String("device_token")!;

        var withHeader = await (await app.Client.Get("/auth/devices", account.AccessToken, deviceToken)).Json();
        var withoutHeader = await (await app.Client.Get("/auth/devices", account.AccessToken)).Json();

        await Assert.That(withHeader[0].Names()).IsEquivalentTo(new[]
        {
            "id", "label", "userAgent", "ipAddress", "createdAt", "lastUsedAt", "expiresAt", "isCurrent",
        });
        await Assert.That(withHeader[0].GetProperty("isCurrent").GetBoolean()).IsTrue();
        await Assert.That(withoutHeader[0].GetProperty("isCurrent").GetBoolean()).IsFalse();
        await Assert.That(withHeader[0].String("label")).IsEqualTo("Ada's laptop");
    }

    [Test]
    public async Task A_recovery_code_never_produces_a_device_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var recoveryCode = (await account.EnrolForRecoveryCodesAsync())[0];

        var challenge = (await app.Client.PostJson(
            "/auth/login",
            new { identifier = account.UserName, password = account.Password })).Json().Result.String("challenge")!;

        var verify = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge, code = recoveryCode, rememberDevice = true });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await verify.Json()).Has("device_token")).IsFalse();
    }

    [Test]
    public async Task A_rehash_on_a_device_trusted_sign_in_survives_a_wrong_password_landing_meanwhile()
    {
        var hasher = new HeldHasher { HashingOnly = true };
        await using var app = await TestApp.StartAsync(configureServices: hasher.Register);

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;
        var userId = Guid.Parse(account.Claims().String("sub")!);

        // Fewer iterations than the app now asks for, so sign-in rehashes.
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var configured = scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<ToamaisutaaLocalLoginOptions>>().Value;
            var weaker = new Toamaisutaa.Core.Pbkdf2PasswordHasher(Microsoft.Extensions.Options.Options.Create(new ToamaisutaaLocalLoginOptions
            {
                Pbkdf2Iterations = 1_000,
                Pepper = configured.Pepper,
                PepperVersion = configured.PepperVersion,
            }));

            var store = scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
            var credential = (await store.FindByUserIdAsync(userId))!;
            credential.PasswordHash = weaker.Hash(account.Password);
            await store.UpdateAsync(credential);
        }

        hasher.Hold = account.Password;
        var signIn = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password, deviceToken });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });
        hasher.Let();

        HttpResponseMessage? response = null;

        try
        {
            response = await signIn;
        }
        catch (Exception)
        {
            // The test server rethrows what the endpoint threw, which is the 500 a real host answers.
        }

        await Assert.That(response?.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await response!.Json()).Has("access_token")).IsTrue();

        // And the rehash still landed, rather than being dropped to get out of the way.
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var stored = (await scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>().FindByUserIdAsync(userId))!;
            var current = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

            await Assert.That(current.Verify(account.Password, stored.PasswordHash)).IsEqualTo(PasswordVerificationResult.Succeeded);
        }
    }
}
