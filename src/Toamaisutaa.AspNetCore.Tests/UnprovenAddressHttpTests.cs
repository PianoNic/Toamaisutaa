using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

public class UnprovenAddressHttpTests
{
    [Test]
    public async Task An_invitation_takes_its_address_back_from_an_unproven_registration()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "newhire@example.com" }, admin.AccessToken);

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = "mallory", email = "newhire@example.com", password = Account.DefaultPassword });

        await Assert.That(squat.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var complete = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = app.IssuedInvitations.Single().Token, userName = "newhire", password = Account.DefaultPassword });

        await Assert.That(complete.StatusCode).IsEqualTo(HttpStatusCode.Created);

        var signIn = await app.Client.PostJson("/auth/login", new { identifier = "newhire@example.com", password = Account.DefaultPassword });
        var claims = Account.DecodeClaims((await signIn.Json()).String("access_token")!);

        await Assert.That(claims.String("sub")).IsEqualTo(Account.DecodeClaims((await complete.Json()).String("access_token")!).String("sub"));

        // A magic link is sent only to a verified address, so it shows from outside that the invitation proved it.
        await app.Client.PostJson("/auth/magic-link", new { email = "newhire@example.com" });
        await Assert.That(app.IssuedMagicLinks).HasCount().EqualTo(1);
    }
}
