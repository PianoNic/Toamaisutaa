using System.Net;

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

        var begin = await app.Client.PostEmpty("/auth/2fa/begin", account.AccessToken);
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
}
