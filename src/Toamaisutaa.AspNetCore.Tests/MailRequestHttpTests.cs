using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The two anonymous endpoints that may send mail, and what the clock and a flood say about them.
/// </summary>
public class MailRequestHttpTests
{
    /// <summary>
    /// The body was always the same 204. The time was not: an unknown address answered after one
    /// lookup and a real one after the mail server did, so timing a list of addresses enumerated
    /// the accounts. A mail server that never answers makes the difference unmissable.
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
    /// Raced rather than cancelled: the in-process server does not abandon a handler when the
    /// client gives up, so a request that waits on the mail server would otherwise hang the run
    /// instead of failing it. The mail server is released either way.
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

    /// <summary>
    /// Each request mailed another link and retired the one before it, so asking over and over from
    /// as many addresses as the limiter allows filled the inbox and left the owner nothing usable.
    /// </summary>
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
