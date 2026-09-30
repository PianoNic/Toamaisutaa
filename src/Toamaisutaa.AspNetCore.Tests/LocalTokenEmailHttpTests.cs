namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Downstream policies read a local token's <c>email</c> as a proven address, so it only carries a verified one.
/// </summary>
public class LocalTokenEmailHttpTests
{
    [Test]
    public async Task A_token_carries_no_email_until_the_address_is_verified()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await Assert.That(account.Claims().String("email")).IsNull();

        var signedIn = await (await account.LoginAsync()).Json();
        await Assert.That(Account.DecodeClaims(signedIn.String("access_token")!).String("email")).IsNull();
    }

    [Test]
    public async Task A_verified_address_is_in_the_token_and_survives_a_refresh()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var signedIn = await (await account.LoginAsync()).Json();
        await Assert.That(Account.DecodeClaims(signedIn.String("access_token")!).String("email")).IsEqualTo(account.Email);

        var refreshed = await (await app.Client.PostJson("/auth/refresh", new { refreshToken = signedIn.String("refresh_token") })).Json();
        await Assert.That(Account.DecodeClaims(refreshed.String("access_token")!).String("email")).IsEqualTo(account.Email);
    }

    [Test]
    public async Task A_step_up_token_carries_the_verified_address_too()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        await account.EnrolAsync();

        var steppedUp = await (await account.StepUpAsync()).Json();

        await Assert.That(Account.DecodeClaims(steppedUp.String("access_token")!).String("email")).IsEqualTo(account.Email);
    }
}
