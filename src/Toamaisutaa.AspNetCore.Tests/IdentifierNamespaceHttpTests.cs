using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The sign-in box takes a user name or an email, so the two are one namespace. The unique indexes
/// only ever compared each column against itself.
/// </summary>
public class IdentifierNamespaceHttpTests
{
    /// <summary>A user name spelled like somebody's address used to take that person's email
    /// sign-ins, and pile their failed attempts onto the squatter's lockout.</summary>
    [Test]
    public async Task A_user_name_equal_to_another_accounts_email_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = victim.Email, email = "mallory@example.com", password = Account.DefaultPassword });

        await Assert.That(squat.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    [Test]
    public async Task An_email_equal_to_another_accounts_user_name_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = "mallory", email = victim.UserName, password = Account.DefaultPassword });

        await Assert.That(squat.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    [Test]
    public async Task Changing_an_email_to_another_accounts_user_name_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);
        var mallory = await Account.RegisterAsync(app, "mallory");

        var change = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = victim.UserName, currentPassword = mallory.Password },
            mallory.AccessToken);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    /// <summary>
    /// A collision already in the database, written straight through the store the way a row from
    /// before the check would have been. Whichever row the database returned first used to answer;
    /// an address-shaped identifier now always means the address.
    /// </summary>
    [Test]
    public async Task An_existing_collision_still_signs_the_owner_of_the_address_in()
    {
        await using var app = await TestApp.StartAsync();
        var mallory = await Account.RegisterAsync(app, "mallory");
        var victim = await Account.RegisterAsync(app);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
            var squatter = (await store.FindByIdentifierAsync("MALLORY"))!;

            squatter.UserName = victim.Email;
            squatter.NormalizedUserName = victim.Email.ToUpperInvariant();
            await store.UpdateAsync(squatter);
        }

        var signIn = await app.Client.PostJson("/auth/login", new { identifier = victim.Email, password = victim.Password });

        await Assert.That(signIn.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(Account.DecodeClaims((await signIn.Json()).String("access_token")!).String("sub"))
            .IsEqualTo(victim.Claims().String("sub"));
    }
}
