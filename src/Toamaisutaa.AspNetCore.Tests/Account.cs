using System.Net;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Drives the endpoints the way a client does, so a test reads as a scenario rather than as
/// plumbing. Everything goes over HTTP - nothing here reaches into a service or a store.
/// </summary>
internal sealed class Account(TestApp app, string userName, string password)
{
    public string UserName { get; } = userName;

    public string Password { get; } = password;

    public string AccessToken { get; private set; } = default!;

    /// <summary>Base32 TOTP secret, once enrolled.</summary>
    public string? Secret { get; private set; }

    public static async Task<Account> RegisterAsync(TestApp app, string userName = "ada")
    {
        var account = new Account(app, userName, "correct horse battery staple");

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName, email = $"{userName}@example.com", password = account.Password });

        if (response.StatusCode != HttpStatusCode.Created)
            throw new InvalidOperationException($"Registration failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        account.AccessToken = (await response.Json()).String("access_token")!;
        return account;
    }

    public Task<HttpResponseMessage> LoginAsync(string? deviceToken = null) =>
        app.Client.PostJson("/auth/login", new { identifier = UserName, password = Password, deviceToken });

    /// <summary>
    /// Enrols and confirms, leaving <see cref="AccessToken"/> refreshed - confirming moves the
    /// security stamp, so the token that confirmed is dead and reusing it would fail every
    /// subsequent call for the wrong reason.
    /// </summary>
    public async Task EnrolAsync()
    {
        var begin = await app.Client.PostEmpty("/auth/2fa/begin", AccessToken);
        Secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();

        var confirm = await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(Secret, app.Time.Now) },
            AccessToken);

        if (confirm.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Confirm failed: {confirm.StatusCode} {await confirm.Content.ReadAsStringAsync()}");

        await SignInWithSecondFactorAsync();
    }

    /// <summary>A full sign-in through the challenge, returning the body of the final response.</summary>
    public async Task<JsonElement> SignInWithSecondFactorAsync(bool rememberDevice = false, string? deviceLabel = null)
    {
        var challenge = (await LoginAsync()).Json().Result.String("challenge")!;

        app.Time.AdvanceToNextTotpStep();

        var verify = await app.Client.PostJson(
            "/auth/2fa/verify",
            new
            {
                challenge,
                code = Totp.Code(Secret!, app.Time.Now),
                rememberDevice,
                deviceLabel,
            });

        if (verify.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Verify failed: {verify.StatusCode} {await verify.Content.ReadAsStringAsync()}");

        var body = await verify.Json();
        AccessToken = body.String("access_token")!;
        return body;
    }
}
