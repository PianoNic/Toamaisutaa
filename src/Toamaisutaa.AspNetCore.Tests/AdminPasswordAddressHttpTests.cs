using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class AdminPasswordAddressHttpTests
{
    /// <summary>The profile field is what an identity provider's sync writes, so it is not trusted
    /// with a password in the clear.</summary>
    [Test]
    public async Task An_admin_password_goes_to_the_credential_address_not_the_profile_email()
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IAdminPasswordIssuedNotifier>(new AddressRecorder(sentTo)));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app);
        var targetId = Guid.Parse(target.Claims().String("sub")!);

        await using (var scope = app.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserStore>().SetEmailAsync(targetId, "attacker@example.net");

        await app.Client.PostJson($"/auth/users/{targetId}/password", new { password = "a chosen password" }, admin.AccessToken);

        await Assert.That(sentTo).IsEquivalentTo(new[] { target.Email });
    }

    [Test]
    public async Task With_verification_required_an_unverified_address_is_not_mailed_a_password()
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:RequireVerifiedEmailForPasswordReset"] = "true",
            configureServices: services => services.AddSingleton<IAdminPasswordIssuedNotifier>(new AddressRecorder(sentTo)));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var target = await Account.RegisterAsync(app);
        var targetId = Guid.Parse(target.Claims().String("sub")!);

        var response = await app.Client.PostJson($"/auth/users/{targetId}/password", new { password = "a chosen password" }, admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(sentTo).IsEmpty();

        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task With_no_credential_address_the_profile_email_is_not_mailed_a_password(bool hasCredential)
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IAdminPasswordIssuedNotifier>(new AddressRecorder(sentTo)));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        Guid targetId;

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<IUserStore>();

            if (hasCredential)
            {
                var target = await Account.RegisterAsync(app);
                targetId = Guid.Parse(target.Claims().String("sub")!);

                var credentials = scope.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
                var credential = (await credentials.FindByUserIdAsync(targetId))!;
                credential.Email = null;
                credential.NormalizedEmail = null;
                await credentials.UpdateAsync(credential);
            }
            else
            {
                targetId = (await users.CreateAsync(new ExternalUserProfile { Subject = "provider-owned", UserName = "grace" })).Id;
            }

            await users.SetEmailAsync(targetId, "attacker@example.net");
        }

        var response = await app.Client.PostJson($"/auth/users/{targetId}/password", new { password = "a chosen password" }, admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(sentTo).IsEquivalentTo(new[] { "(no address)" });
    }

    /// <summary>With no address nothing is mailed, so refusing would only take away the one recovery
    /// path left.</summary>
    [Test]
    public async Task With_verification_required_an_account_with_no_address_can_still_be_given_a_password()
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:RequireVerifiedEmailForPasswordReset"] = "true",
            configureServices: services => services.AddSingleton<IAdminPasswordIssuedNotifier>(new AddressRecorder(sentTo)));

        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var register = await app.Client.PostJson("/auth/register", new { userName = "noaddress", password = Account.DefaultPassword });
        var targetId = Guid.Parse(Account.DecodeClaims((await register.Json()).String("access_token")!).String("sub")!);

        var response = await app.Client.PostJson($"/auth/users/{targetId}/password", new { password = "a chosen password" }, admin.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    private sealed class AddressRecorder(List<string> sentTo) : IAdminPasswordIssuedNotifier
    {
        public Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default)
        {
            sentTo.Add(user.Email ?? "(no address)");
            return Task.CompletedTask;
        }
    }
}
