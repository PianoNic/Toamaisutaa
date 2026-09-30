using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The device token across two sign-ins.
/// </summary>
/// <remarks>
/// This is the bug that started the suite. The service layer was correct throughout - the gate
/// rotated the token, the store recorded it, <c>SignInResult.TrustedDevice</c> was populated - and
/// the endpoint returned only the token pair. The caller kept holding a spent token, presented it
/// on the next sign-in, and that is the theft signal, so the device silently stopped working after
/// exactly one use. Nothing below the wire could see it.
/// </remarks>
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

        // No challenge: the cached second factor stood in for the live one.
        await Assert.That(second.Has("two_factor_required")).IsFalse();
        await Assert.That(second.String("access_token")).IsNotNull();

        // The rotation, which the endpoint used to drop.
        var rotated = second.String("device_token");
        await Assert.That(rotated).IsNotNull();
        await Assert.That(rotated).IsNotEqualTo(issued);
    }

    /// <summary>
    /// The exact sequence the dropped-token bug produced: hold the old token because the response
    /// never carried the new one, present it again, lose the device.
    /// </summary>
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

    /// <summary>
    /// Rotation marked the row spent whatever it held, so every request presenting one copied token
    /// at once passed the checks, got a session that skipped the second factor, and minted a live
    /// successor of its own - and none of it looked like reuse.
    /// </summary>
    [Test]
    public async Task A_device_token_presented_in_parallel_skips_the_second_factor_at_most_once()
    {
        var store = new MeetBeforeRotating();
        await using var app = await TestApp.StartAsync(configureServices: store.Register);

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var issued = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        // Both past every check and waiting at the write, which is where a real race puts them.
        store.Hold = true;
        var attempts = await Task.WhenAll(account.LoginAsync(deviceToken: issued), account.LoginAsync(deviceToken: issued));
        var bodies = await Task.WhenAll(attempts.Select(response => response.Json()));

        await Assert.That(bodies.Count(body => body.Has("access_token"))).IsLessThanOrEqualTo(1);
    }

    /// <summary>The real store, except that the first two rotations wait for each other.</summary>
    private sealed class MeetBeforeRotating
    {
        private readonly CountdownEvent _arrived = new(2);

        internal volatile bool Hold;

        internal void Register(IServiceCollection services)
        {
            // Registered by type, so built here the way the container would have built it.
            var real = services.Last(descriptor => descriptor.ServiceType == typeof(ITrustedDeviceStore)).ImplementationType!;
            services.AddScoped<ITrustedDeviceStore>(provider =>
                new Held(this, (ITrustedDeviceStore)ActivatorUtilities.CreateInstance(provider, real)));
        }

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

        // Rotation must not restart the thirty days, or a device signed in from monthly would never
        // expire and "absolute lifetime" would mean nothing.
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

    /// <summary>A recovery code means the authenticator is gone, so it revokes trust rather than
    /// establishing it - however loudly the caller asked to be remembered.</summary>
    [Test]
    public async Task A_recovery_code_never_produces_a_device_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(secret, app.Time.Now) },
            account.AccessToken);

        var recoveryCode = (await confirm.Json()).GetProperty("recoveryCodes")[0].GetString()!;

        var challenge = (await app.Client.PostJson(
            "/auth/login",
            new { identifier = account.UserName, password = account.Password })).Json().Result.String("challenge")!;

        var verify = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge, code = recoveryCode, rememberDevice = true });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await verify.Json()).Has("device_token")).IsFalse();
    }

    /// <summary>
    /// A password stored under older parameters is rehashed on sign-in, and the rehash was set on the
    /// tracked credential and left there. The trusted-device insert saved it, unguarded, against a
    /// row a wrong password had moved in the meantime: a 500, after the old device row was already
    /// spent, so the device lost its trust as well.
    /// </summary>
    [Test]
    public async Task A_rehash_on_a_device_trusted_sign_in_survives_a_wrong_password_landing_meanwhile()
    {
        var hasher = new HeldHasher { HashingOnly = true };
        await using var app = await TestApp.StartAsync(configureServices: hasher.Register);

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;
        var userId = Guid.Parse(account.Claims().String("sub")!);

        // Stored under fewer iterations than the app now asks for, which is what asks for a rehash.
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
