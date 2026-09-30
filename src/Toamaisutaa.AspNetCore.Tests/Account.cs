using System.Net;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

internal sealed class Account(TestApp app, string userName, string password)
{
    public const string DefaultPassword = "correct horse battery staple";

    public string UserName { get; } = userName;

    public string Password { get; } = password;

    public string Email { get; } = $"{userName}@example.com";

    public string AccessToken { get; private set; } = default!;

    public string? Secret { get; private set; }

    public static async Task<Account> RegisterAsync(TestApp app, string userName = "ada")
    {
        var account = new Account(app, userName, DefaultPassword);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName, email = $"{userName}@example.com", password = account.Password });

        if (response.StatusCode != HttpStatusCode.Created)
            throw new InvalidOperationException($"Registration failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        account.AccessToken = (await response.Json()).String("access_token")!;
        return account;
    }

    /// <summary>Asking to change to the address already held is the documented way to verify it.</summary>
    public async Task VerifyEmailAsync()
    {
        var request = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = Email, currentPassword = Password },
            AccessToken);

        if (request.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Email change failed: {request.StatusCode} {await request.Content.ReadAsStringAsync()}");

        var verify = await app.Client.PostJson(
            "/auth/email/verify",
            new { token = app.IssuedEmailVerifications[^1].Token });

        if (verify.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Email verification failed: {verify.StatusCode} {await verify.Content.ReadAsStringAsync()}");
    }

    public async Task<string> RequestMagicLinkAsync()
    {
        var response = await app.Client.PostJson("/auth/magic-link", new { email = Email });

        if (response.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Magic-link request failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");

        return app.IssuedMagicLinks[^1].Token;
    }

    public Task<HttpResponseMessage> LoginAsync(string? deviceToken = null) =>
        app.Client.PostJson("/auth/login", new { identifier = UserName, password = Password, deviceToken });

    /// <summary>Confirming moves the security stamp, so this signs in again rather than leave a dead
    /// <see cref="AccessToken"/> failing later calls for the wrong reason.</summary>
    public async Task EnrolAsync()
    {
        await EnrolForRecoveryCodesAsync();
        await SignInWithSecondFactorAsync();
    }

    /// <summary>
    /// Enrols and confirms, handing back the recovery codes confirming returns once and never again.
    /// Unlike <see cref="EnrolAsync"/> it does not sign in afterwards, so <see cref="AccessToken"/> is
    /// left as the token confirming made stale.
    /// </summary>
    public async Task<IReadOnlyList<string>> EnrolForRecoveryCodesAsync()
    {
        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = Password }, AccessToken);
        Secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();

        var confirm = await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(Secret, app.Time.Now) },
            AccessToken);

        if (confirm.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Confirm failed: {confirm.StatusCode} {await confirm.Content.ReadAsStringAsync()}");

        return (await confirm.Json()).Strings("recoveryCodes");
    }

    public async Task<HttpResponseMessage> StepUpAsync(string? code = null, string? accessToken = null)
    {
        var token = accessToken ?? AccessToken;
        var begin = await app.Client.PostEmpty("/auth/2fa/step-up", token);

        if (begin.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException($"Step-up begin failed: {begin.StatusCode} {await begin.Content.ReadAsStringAsync()}");

        var challenge = (await begin.Json()).String("challenge")!;

        if (code is null)
            app.Time.AdvanceToNextTotpStep();

        return await app.Client.PostJson(
            "/auth/2fa/step-up/verify",
            new { challenge, code = code ?? Totp.Code(Secret!, app.Time.Now) },
            token);
    }

    public JsonElement Claims() => DecodeClaims(AccessToken);

    public static JsonElement DecodeClaims(string accessToken)
    {
        var payload = accessToken.Split('.')[1];
        var padded = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');
        var bytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));

        return JsonDocument.Parse(bytes).RootElement.Clone();
    }

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
