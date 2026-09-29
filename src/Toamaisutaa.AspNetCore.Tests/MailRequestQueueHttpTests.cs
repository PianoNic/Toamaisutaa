using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The queue reset and magic-link requests wait in after their 204 has gone.
/// </summary>
public class MailRequestQueueHttpTests
{
    /// <summary>
    /// One reader drained at the speed of one SMTP conversation, so anyone asking about enough
    /// addresses kept the queue full and every real request behind them was dropped. Two jobs where
    /// the first waits on the second only finish if more than one runs at once.
    /// </summary>
    [Test]
    public async Task Queued_requests_run_side_by_side()
    {
        await using var app = await TestApp.StartAsync();
        var queue = app.Services.GetRequiredService<MailRequestQueue>();

        var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstSawSecond = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        queue.Enqueue(async (_, _) =>
            firstSawSecond.SetResult(await Task.WhenAny(second.Task, Task.Delay(TimeSpan.FromSeconds(10))) == second.Task));
        queue.Enqueue((_, _) =>
        {
            second.SetResult();
            return Task.CompletedTask;
        });

        await Assert.That(await firstSawSecond.Task).IsTrue();
    }

    /// <summary>
    /// A request dropped from a full queue sent nothing, but its address had already taken the
    /// cooldown, so the owner's retry a moment later was turned away too - two requests, no mail.
    /// </summary>
    [Test]
    [Arguments("/auth/password/forgot")]
    [Arguments("/auth/magic-link")]
    public async Task A_request_dropped_from_a_full_queue_is_counted_and_leaves_the_retry_free(string path)
    {
        var resets = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00",
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new ResetCapture(resets)));

        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var queue = app.Services.GetRequiredService<MailRequestQueue>();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = 0;

        Task Held(IServiceProvider _, CancellationToken __)
        {
            Interlocked.Increment(ref started);
            return gate.Task;
        }

        // Every reader holding a job first, so none of them frees a slot after the queue is full.
        for (var i = 0; i < MailRequestQueue.Readers; i++)
            queue.Enqueue(Held);

        while (Volatile.Read(ref started) < MailRequestQueue.Readers)
            await Task.Delay(5);

        var filled = false;
        for (var i = 0; i < 5000 && !filled; i++)
            filled = !queue.Enqueue(Held);

        await Assert.That(filled).IsTrue();

        using var dropped = new InstrumentProbe(app, "toamaisutaa.mail_requests.dropped");

        // Raw, because the usual client waits for the queue to drain, and this one is held full.
        await app.RawClient.PostJson(path, new { email = account.Email });
        await Assert.That(dropped.Total).IsEqualTo(1);

        gate.SetResult();
        await queue.WhenIdleAsync();

        await app.Client.PostJson(path, new { email = account.Email });

        await Assert.That(resets.Count + app.IssuedMagicLinks.Count).IsEqualTo(1);
    }

    private sealed class ResetCapture(List<string> issued) : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
        {
            lock (issued)
                issued.Add(resetToken);

            return Task.CompletedTask;
        }
    }
}
