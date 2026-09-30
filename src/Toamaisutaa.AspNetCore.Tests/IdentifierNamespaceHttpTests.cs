using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class IdentifierNamespaceHttpTests
{
    [Test]
    public async Task A_user_name_equal_to_another_accounts_email_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = victim.Email, email = "mallory@example.com", password = Account.DefaultPassword });

        await Assert.That(squat.IsSuccessStatusCode).IsFalse();
    }

    [Test]
    public async Task A_user_name_shaped_like_an_address_is_refused()
    {
        await using var app = await TestApp.StartAsync();

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = "newhire@example.com", password = Account.DefaultPassword });

        await Assert.That(squat.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task An_address_with_anything_around_it_is_refused_at_registration()
    {
        await using var app = await TestApp.StartAsync();

        var register = await app.Client.PostJson(
            "/auth/register",
            new { userName = "mallory", email = Dressed, password = Account.DefaultPassword });

        await Assert.That(register.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task An_address_with_anything_around_it_is_refused_as_a_new_email()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var change = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = Dressed, currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    private const string Dressed = "\"Payroll on hold - https://evil.example\" <victim@example.com>";

    /// <summary>Address-shaped user names from before that rule still exist, so the store is written to
    /// directly to produce one.</summary>
    [Test]
    public async Task An_email_equal_to_another_accounts_user_name_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);
        await GiveAnAddressShapedUserNameAsync(app, victim.UserName, LegacyUserName);

        var squat = await app.Client.PostJson(
            "/auth/register",
            new { userName = "mallory", email = LegacyUserName, password = Account.DefaultPassword });

        await Assert.That(squat.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    [Test]
    public async Task Changing_an_email_to_another_accounts_user_name_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app);
        await GiveAnAddressShapedUserNameAsync(app, victim.UserName, LegacyUserName);
        var mallory = await Account.RegisterAsync(app, "mallory");

        var change = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = LegacyUserName, currentPassword = mallory.Password },
            mallory.AccessToken);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    private const string LegacyUserName = "legacy@example.com";

    private static async Task GiveAnAddressShapedUserNameAsync(TestApp app, string userName, string address)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
        var credential = (await store.FindByIdentifierAsync(userName.ToUpperInvariant()))!;

        credential.UserName = address;
        credential.NormalizedUserName = address.ToUpperInvariant();
        await store.UpdateAsync(credential);
    }

    /// <summary>With a collision already in the database, an address-shaped identifier must mean the
    /// address rather than whichever row the database returns first.</summary>
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
