using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An address nobody has proven is not somebody's to keep. Registration takes whatever it is typed,
/// and it used to reserve that address in the unique index for good.
/// </summary>
public class UnprovenAddressHttpTests
{
    /// <summary>
    /// Somebody registers a new hire's address before the invitation lands. The invitee used to get
    /// a 409 for every user name they tried, with nothing in band to put it right.
    /// </summary>
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

        // And the address now signs in the person the invitation reached, not the one who typed it first.
        var signIn = await app.Client.PostJson("/auth/login", new { identifier = "newhire@example.com", password = Account.DefaultPassword });
        var claims = Account.DecodeClaims((await signIn.Json()).String("access_token")!);

        await Assert.That(claims.String("sub")).IsEqualTo(Account.DecodeClaims((await complete.Json()).String("access_token")!).String("sub"));

        // The invitation reached this mailbox and came back, so the address counts as proven -
        // which a magic link, sent only to a verified address, is the way to see from outside.
        await app.Client.PostJson("/auth/magic-link", new { email = "newhire@example.com" });
        await Assert.That(app.IssuedMagicLinks).HasCount().EqualTo(1);
    }
}
