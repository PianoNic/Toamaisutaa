using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A reset request always answers 204 so the response cannot reveal whether an account exists.
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
