using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// docs/password-login.md promises "Requesting a reset always answers 204" - the whole point being
/// that a caller cannot tell a real account from an unknown one by the response. A real
/// <c>IPasswordResetNotifier</c> can throw for reasons that have nothing to do with the account, and
/// nothing may turn that into anything but 204.
/// </summary>
public class PasswordResetNotifierHttpTests
{
    [Test]
    public async Task A_notifier_failure_still_answers_204_rather_than_500()
    {
        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier, ThrowingResetNotifier>());

        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/password/forgot", new { email = $"{account.UserName}@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    private sealed class ThrowingResetNotifier : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the mail server is down");
    }
}
