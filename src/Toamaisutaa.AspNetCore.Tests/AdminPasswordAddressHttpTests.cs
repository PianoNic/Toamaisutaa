using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An administrator-set password goes out in the clear. Where it goes has to be an address the
/// account has, and one that somebody proved when the deployment asks for that.
/// </summary>
public class AdminPasswordAddressHttpTests
{
    /// <summary>The profile field is what an identity provider's sync writes; the credential's
    /// address is the one the account signs in with.</summary>
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

    /// <summary>
    /// With the option on, a self-service reset will not mail an unproven address. A password in the
    /// clear is a better prize than a reset link, and it went there anyway.
    /// </summary>
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

        // Refused before anything moved: the owner's own password still works.
        await Assert.That((await target.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.OK);
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
