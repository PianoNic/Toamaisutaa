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

    /// <summary>
    /// Readers walked away from a hung job and started the next straight away, while the hung one
    /// kept its thread and scope. Against a mail server that stops answering, jobs piled up without
    /// limit, so this checks no more than the cap ever start.
    /// </summary>
    [Test]
    public async Task Hung_jobs_count_against_the_limit_after_they_are_abandoned()
    {
        await using var app = await TestApp.StartAsync();
        var queue = app.Services.GetRequiredService<MailRequestQueue>();
        queue.JobTimeout = TimeSpan.FromMilliseconds(50);

        using var blocked = new ManualResetEventSlim();
        var started = 0;

        for (var i = 0; i < MailRequestQueue.MaxInFlight + 10; i++)
        {
            queue.Enqueue((_, _) =>
            {
                Interlocked.Increment(ref started);
                blocked.Wait();
                return Task.CompletedTask;
            });
        }

        // Each job holds a thread-pool thread, and under a full suite the pool grows slowly, so wait for
        // the cap to be reached rather than for a fixed time.
        for (var i = 0; i < 300 && Volatile.Read(ref started) < MailRequestQueue.MaxInFlight; i++)
            await Task.Delay(100);

        // Then long enough for every reader to abandon its job many times over, which is when a queue
        // without the cap would start more.
        await Task.Delay(TimeSpan.FromSeconds(2));
        var reached = Volatile.Read(ref started);

        blocked.Set();

        // Idle means every reader is done with its job, not that the job ran, so wait for the jobs.
        for (var i = 0; i < 300 && Volatile.Read(ref started) < MailRequestQueue.MaxInFlight + 10; i++)
            await Task.Delay(100);

        await Assert.That(reached).IsEqualTo(MailRequestQueue.MaxInFlight);
        await Assert.That(Volatile.Read(ref started)).IsEqualTo(MailRequestQueue.MaxInFlight + 10);
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
