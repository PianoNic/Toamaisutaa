using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Runs anonymous mail-sending requests after the response, so response time cannot reveal which
/// addresses have accounts; several readers, so one slow SMTP server cannot keep the bounded queue full.
/// </summary>
internal sealed class MailRequestQueue(IServiceScopeFactory scopes, ToamaisutaaMetrics metrics, ILogger<MailRequestQueue> logger) : BackgroundService
{
    private const int Capacity = 1000;

    // ponytail: a fixed width - a setting when somebody's mail server wants more or fewer connections.
    internal const int Readers = 8;

    // Wait, not DropWrite: DropWrite makes TryWrite return true for the item it discards, hiding drops.
    private readonly Channel<Func<IServiceProvider, CancellationToken, Task>> _work =
        Channel.CreateBounded<Func<IServiceProvider, CancellationToken, Task>>(
            new BoundedChannelOptions(Capacity) { FullMode = BoundedChannelFullMode.Wait });

    /// <summary>
    /// Jobs running at once, abandoned ones included: a reader walks away from a hung job, but the job
    /// keeps its thread and scope until it ends, so without a cap a hung mail server leaks both.
    /// </summary>
    internal const int MaxInFlight = Readers * 4;

    private readonly SemaphoreSlim _inFlight = new(MaxInFlight, MaxInFlight);

    private int _pending;

    internal TimeSpan JobTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Runs work in a scope of its own, since the request's scope is gone by the time it starts.</summary>
    internal bool Enqueue(Func<IServiceProvider, CancellationToken, Task> work)
    {
        Interlocked.Increment(ref _pending);

        if (_work.Writer.TryWrite(work))
            return true;

        Interlocked.Decrement(ref _pending);
        metrics.MailRequestDropped();
        logger.LogError("The mail request queue is full; a reset or magic-link request was dropped without being processed.");

        return false;
    }

    internal async Task WhenIdleAsync()
    {
        while (Volatile.Read(ref _pending) > 0)
            await Task.Delay(5);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.WhenAll(Enumerable.Range(0, Readers).Select(_ => ReadAsync(stoppingToken)));

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);

        // Already answered 204, so the only trace these ever leave is this line.
        var dropped = 0;

        while (_work.Reader.TryRead(out _))
        {
            dropped++;
            Interlocked.Decrement(ref _pending);
        }

        if (dropped > 0)
            logger.LogWarning("{Count} queued reset or magic-link request(s) were dropped because the host stopped.", dropped);
    }

    private async Task ReadAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var work in _work.Reader.ReadAllAsync(stoppingToken))
            {
                var deadline = CancellationToken.None;

                try
                {
                    // A slot first, held until the job really ends, so jobs abandoned below still count.
                    await _inFlight.WaitAsync(stoppingToken);

                    // Started once there is a slot, or a job that waited for one is abandoned on arrival.
                    var source = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    source.CancelAfter(JobTimeout);
                    deadline = source.Token;

                    // Stops waiting at the deadline even when the job ignores its token, and off this
                    // thread, because a synchronous SMTP send blocks before it returns a task to wait
                    // on. The job owns its scope and its deadline until it does finish: disposed when
                    // this reader moved on, a job that had not started yet failed without sending.
                    await Task.Run(
                        async () =>
                        {
                            try
                            {
                                await RunInScopeAsync(work, deadline);
                            }
                            finally
                            {
                                source.Dispose();
                                _inFlight.Release();
                            }
                        },
                        CancellationToken.None).WaitAsync(deadline);
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested && !stoppingToken.IsCancellationRequested)
                {
                    logger.LogError(
                        "A queued reset or magic-link request was abandoned after {Timeout}. It is still running and may yet send its mail.",
                        JobTimeout);
                }
                catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
                {
                    logger.LogError(exception, "A queued reset or magic-link request failed.");
                }
                catch (OperationCanceledException)
                {
                    logger.LogWarning("A queued reset or magic-link request was cut off because the host stopped.");
                }
                finally
                {
                    Interlocked.Decrement(ref _pending);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task RunInScopeAsync(Func<IServiceProvider, CancellationToken, Task> work, CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        await work(scope.ServiceProvider, cancellationToken);
    }
}
