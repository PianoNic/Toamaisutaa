using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The per-address cooldown in front of the anonymous mail endpoints, which remembers what it was
/// asked about in the process's own memory.
/// </summary>
public class MailRequestCooldownHttpTests
{
    private static Task<TestApp> StartAsync(Action<IServiceCollection>? configureServices = null) =>
        TestApp.StartAsync(
            configure: settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00",
            configureServices: configureServices);

    /// <summary>
    /// The body has no length limit short of Kestrel's 30 MB, and whatever arrived was kept as the
    /// key for a minute or, below the sweep threshold, for good. Ten of those a minute from one
    /// address ran the process out of memory.
    /// </summary>
    [Test]
    [Arguments("/auth/password/forgot")]
    [Arguments("/auth/magic-link")]
    public async Task Something_too_long_to_be_an_address_is_not_remembered(string path)
    {
        await using var app = await StartAsync();
        var cooldown = app.Services.GetRequiredService<MailRequestCooldown>();

        var response = await app.Client.PostJson(path, new { email = new string('a', 100_000) + "@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(cooldown.Count).IsEqualTo(0);
    }

    /// <summary>Expired entries were only swept once ten thousand had built up, so anything
    /// below that was never let go at all.</summary>
    [Test]
    public async Task Expired_addresses_are_let_go_without_waiting_for_a_crowd()
    {
        await using var app = await StartAsync();
        var cooldown = app.Services.GetRequiredService<MailRequestCooldown>();

        for (var i = 0; i < 3; i++)
            await app.Client.PostJson("/auth/password/forgot", new { email = $"nobody{i}@example.com" });

        app.Time.Advance(TimeSpan.FromMinutes(2));
        await app.Client.PostJson("/auth/password/forgot", new { email = "somebody@example.com" });

        await Assert.That(cooldown.Count).IsEqualTo(1);
    }

    /// <summary>
    /// The cooldown was handed back only for a request that failed politely. One whose mail server
    /// timed out answered 500, sent nothing, and the retry was told a link went out a moment ago.
    /// </summary>
    [Test]
    public async Task An_email_change_that_throws_leaves_the_retry_free()
    {
        var notifier = new FailsOnce();
        await using var app = await StartAsync(services => services.AddSingleton<IEmailVerificationNotifier>(notifier));
        var account = await Account.RegisterAsync(app);

        HttpResponseMessage? failed = null;

        try
        {
            failed = await app.Client.PostJson("/auth/email", new { newEmail = account.Email, currentPassword = account.Password }, account.AccessToken);
        }
        catch (Exception)
        {
            // The test server rethrows what the endpoint threw, which is the 500 a real host answers.
        }

        await Assert.That(failed?.IsSuccessStatusCode ?? false).IsFalse();

        var retry = await app.Client.PostJson("/auth/email", new { newEmail = account.Email, currentPassword = account.Password }, account.AccessToken);

        await Assert.That(retry.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    /// <summary>"Wait a minute" was written into the answer, whatever the cooldown was set to.</summary>
    [Test]
    public async Task The_email_change_cooldown_answer_names_the_configured_wait()
    {
        await using var app = await TestApp.StartAsync(configure: settings => settings["LocalLogin:MailRequestCooldown"] = "00:10:00");
        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/email", new { newEmail = account.Email, currentPassword = account.Password }, account.AccessToken);
        var again = await app.Client.PostJson("/auth/email", new { newEmail = account.Email, currentPassword = account.Password }, account.AccessToken);

        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(string.Join(" ", (await again.Json()).Strings("errors"))).Contains("10 minutes");
    }

    private sealed class FailsOnce : IEmailVerificationNotifier
    {
        private int _calls;

        public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default) =>
            Interlocked.Increment(ref _calls) == 1
                ? throw new TimeoutException("The mail server did not answer.")
                : Task.CompletedTask;
    }
}
