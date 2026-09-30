using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class MailRequestQueueHttpTests
{
    /// <summary>
    /// The first job waits on the second, so both finish only if more than one reader runs at once.
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

    [Test]
    public async Task A_job_that_never_finishes_is_abandoned_at_its_deadline()
    {
        await using var app = await TestApp.StartAsync();
        var queue = app.Services.GetRequiredService<MailRequestQueue>();
        queue.JobTimeout = TimeSpan.FromMilliseconds(200);

        // Ignores its token, as SmtpClient.Send or any call made without it does. One that honoured
        // the token would finish on cancellation and prove only that the token was cancelled.
        // Half hand back a task that never completes, half block the calling thread before returning one.
        var never = new TaskCompletionSource();
        using var blocked = new ManualResetEventSlim();

        for (var i = 0; i < MailRequestQueue.Readers; i++)
        {
            if (i % 2 == 0)
            {
                queue.Enqueue((_, _) => never.Task);
            }
            else
            {
                queue.Enqueue((_, _) =>
                {
                    blocked.Wait();
                    return Task.CompletedTask;
                });
            }
        }

        var ran = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        queue.Enqueue((_, _) =>
        {
            ran.TrySetResult();
            return Task.CompletedTask;
        });

        // Every reader was holding a stuck job, so this runs only if they let go of them.
        await ran.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await queue.WhenIdleAsync().WaitAsync(TimeSpan.FromSeconds(10));

        never.SetResult();
        blocked.Set();
    }

    [Test]
    [Arguments("/auth/password/forgot")]
    [Arguments("/auth/magic-link")]
    public async Task A_request_dropped_from_a_full_queue_is_counted_and_leaves_the_retry_free(string path)
    {
        var resets = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:MailRequestCooldown"] = "00:01:00",
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets)));

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

        // Every reader holds a job first, so none frees a slot after the queue is full.
        for (var i = 0; i < MailRequestQueue.Readers; i++)
            queue.Enqueue(Held);

        while (Volatile.Read(ref started) < MailRequestQueue.Readers)
            await Task.Delay(5);

        var filled = false;
        for (var i = 0; i < 5000 && !filled; i++)
            filled = !queue.Enqueue(Held);

        await Assert.That(filled).IsTrue();

        using var dropped = new InstrumentProbe(app, "toamaisutaa.mail_requests.dropped");

        // Raw, because the usual client waits for the queue to drain and this one is held full.
        await app.RawClient.PostJson(path, new { email = account.Email });
        await Assert.That(dropped.Total).IsEqualTo(1);

        gate.SetResult();
        await queue.WhenIdleAsync();

        await app.Client.PostJson(path, new { email = account.Email });

        await Assert.That(resets.Count + app.IssuedMagicLinks.Count).IsEqualTo(1);
    }
}
