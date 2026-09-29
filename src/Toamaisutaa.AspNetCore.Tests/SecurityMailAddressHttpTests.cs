using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Reset and magic links go to the address that was checked. The profile email is a different
/// field, and an identity provider's sync writes it whenever the provider's copy changes.
/// </summary>
public class SecurityMailAddressHttpTests
{
    [Test]
    public async Task A_magic_link_goes_to_the_verified_address_not_the_profile_email()
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IMagicLinkNotifier>(new AddressRecorder(sentTo)));

        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        await ProfileSyncWritesAsync(app, account, "attacker@example.net");

        await app.Client.PostJson("/auth/magic-link", new { email = account.Email });

        await Assert.That(sentTo).IsEquivalentTo(new[] { account.Email });
    }

    [Test]
    public async Task A_reset_link_goes_to_the_credential_address_not_the_profile_email()
    {
        var sentTo = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new AddressRecorder(sentTo)));

        var account = await Account.RegisterAsync(app);
        await ProfileSyncWritesAsync(app, account, "attacker@example.net");

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });

        await Assert.That(sentTo).IsEquivalentTo(new[] { account.Email });
    }

    /// <summary>What a profile sync from the identity provider does to the user row, written the
    /// same way: the profile email moves and the credential does not.</summary>
    private static async Task ProfileSyncWritesAsync(TestApp app, Account account, string email)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await scope.ServiceProvider.GetRequiredService<IUserStore>().SetEmailAsync(userId, email);
    }

    private sealed class AddressRecorder(List<string> sentTo) : IMagicLinkNotifier, IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string token, CancellationToken cancellationToken = default)
        {
            sentTo.Add(user.Email ?? "(no address)");
            return Task.CompletedTask;
        }
    }
}
