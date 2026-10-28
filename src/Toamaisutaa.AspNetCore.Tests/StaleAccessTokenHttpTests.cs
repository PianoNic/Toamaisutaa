using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Against an endpoint that never resolves the current user, so nothing but the bearer layer can
/// refuse the token.
/// </summary>
public class StaleAccessTokenHttpTests
{
    private const string PlainEndpoint = "/test/plain";

    [Test]
    public async Task An_admin_endpoint_refuses_an_admin_token_issued_before_a_password_change()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "target");
        var stolen = admin.AccessToken;

        await ChangePasswordAsync(app, admin);

        var withStolen = await app.Client.PostEmpty($"/auth/users/{Account.DecodeClaims(target.AccessToken).String("sub")}/sessions/revoke", stolen);

        await Assert.That(withStolen.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task An_admin_endpoint_still_accepts_a_current_admin_token()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app, "target");

        var response = await app.Client.PostEmpty($"/auth/users/{Account.DecodeClaims(target.AccessToken).String("sub")}/sessions/revoke", admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    [Test]
    public async Task With_the_check_off_an_ordinary_endpoint_accepts_a_stale_token_until_it_expires()
    {
        await using var app = await TestApp.StartAsync(mapExtra: MapPlain);
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await ChangePasswordAsync(app, account);

        await Assert.That((await app.Client.Get(PlainEndpoint, stale)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task With_the_check_on_an_ordinary_endpoint_refuses_a_stale_token_and_accepts_a_current_one()
    {
        await using var app = await TestApp.StartAsync(
            mapExtra: MapPlain,
            configure: settings => settings["LocalLogin:CheckSecurityStampOnEveryRequest"] = "true");

        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await ChangePasswordAsync(app, account);

        var fresh = (await (await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = NewPassword })).Json())
            .String("access_token")!;

        await Assert.That((await app.Client.Get(PlainEndpoint, stale)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await app.Client.Get(PlainEndpoint, fresh)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>JwtBearer's default leeway is five minutes, which a token a minute past expiry is well inside.</summary>
    [Test]
    public async Task A_token_a_minute_past_its_expiry_is_refused()
    {
        await using var app = await TestApp.StartAsync(mapExtra: MapPlain, configure: settings => settings.Remove("Oidc:ClockSkew"));
        var now = DateTime.UtcNow;

        var expired = Mint(issuedAt: now.AddMinutes(-16), expires: now.AddMinutes(-1));
        var current = Mint(issuedAt: now.AddMinutes(-1), expires: now.AddMinutes(14));

        await Assert.That((await app.Client.Get(PlainEndpoint, expired)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await app.Client.Get(PlainEndpoint, current)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    private const string NewPassword = "a brand new correct horse";

    private static void MapPlain(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet(PlainEndpoint, () => Results.Ok()).RequireAuthorization();

    private static async Task ChangePasswordAsync(TestApp app, Account account)
    {
        var changed = await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = NewPassword },
            account.AccessToken);

        if (changed.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Password change failed: {changed.StatusCode} {await changed.Content.ReadAsStringAsync()}");
    }

    /// <summary>The bearer handler checks lifetimes against the system clock, so these use it too.</summary>
    private static string Mint(DateTime issuedAt, DateTime expires)
    {
        var key = new SymmetricSecurityKey(new byte[32]) { KeyId = ToamaisutaaDefaults.LocalSigningKeyId };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "toamaisutaa-tests",
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity([new Claim("sub", Guid.NewGuid().ToString())]),
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = expires,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        });
    }
}
