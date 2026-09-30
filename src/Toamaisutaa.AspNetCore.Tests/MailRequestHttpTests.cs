using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class MailRequestHttpTests
{
    /// <summary>
    /// Waiting on the mail server only for real accounts would let response timing enumerate them.
    /// </summary>
    [Test]
    public async Task A_reset_request_answers_without_waiting_for_the_mail_server()
    {
        var mailServer = new TaskCompletionSource();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new StalledResetNotifier(mailServer.Task)));

        var account = await Account.RegisterAsync(app);

        await AssertAnswersBeforeTheMailServerAsync(app, "/auth/password/forgot", account.Email, mailServer);
    }

    [Test]
    public async Task A_magic_link_request_answers_without_waiting_for_the_mail_server()
    {
        var mailServer = new TaskCompletionSource();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IMagicLinkNotifier>(new StalledMagicLinkNotifier(mailServer.Task)));

        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        await AssertAnswersBeforeTheMailServerAsync(app, "/auth/magic-link", account.Email, mailServer);
    }

    /// <summary>
    /// Raced rather than cancelled, because the in-process server does not abandon a handler when the client gives up and the run would hang.
    /// </summary>
    private static async Task AssertAnswersBeforeTheMailServerAsync(TestApp app, string path, string email, TaskCompletionSource mailServer)
    {
        try
        {
            var request = app.RawClient.PostAsJsonAsync(path, new { email });
            var first = await Task.WhenAny(request, Task.Delay(TimeSpan.FromSeconds(10)));

            await Assert.That(ReferenceEquals(first, request)).IsTrue();
            await Assert.That((await request).StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        }
        finally
        {
            mailServer.TrySetResult();
        }
    }

    [Test]
    public async Task A_second_reset_request_for_one_address_inside_the_cooldown_sends_nothing()
    {
        var sent = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00",
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(sent)));

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email.ToUpperInvariant() });

        await Assert.That(sent.Count).IsEqualTo(1);

        app.Time.Advance(TimeSpan.FromMinutes(1));
        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });

        await Assert.That(sent.Count).IsEqualTo(2);
    }

    private sealed class StalledResetNotifier(Task mailServer) : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default) => mailServer;
    }

    private sealed class StalledMagicLinkNotifier(Task mailServer) : IMagicLinkNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default) => mailServer;
    }
}
