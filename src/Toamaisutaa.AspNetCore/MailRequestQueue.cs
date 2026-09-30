using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// The anonymous requests that may send mail - a reset link, a magic link - run here, after the
/// response has gone.
/// </summary>
/// <remarks>
/// <para>
/// Every branch of those endpoints answers the same 204, and that promise was only ever half kept:
/// an unknown address returned after one lookup while a real one waited on an SMTP connection, so
/// the clock told a caller which addresses had accounts. Doing the work here makes the response
/// time the same for all of them, because none of them waits for any of it.
/// </para>
/// <para>
/// Bounded, and a full queue drops the request rather than growing. Several readers, because one
/// drained at the speed of a single SMTP conversation, and anyone asking about enough addresses
/// could keep it full so that every real request behind them was dropped.
/// </para>
/// </remarks>
internal sealed class MailRequestQueue(IServiceScopeFactory scopes, ToamaisutaaMetrics metrics, ILogger<MailRequestQueue> logger) : BackgroundService
{
    private const int Capacity = 1000;

    // ponytail: a fixed width - a setting when somebody's mail server wants more or fewer connections.
    internal const int Readers = 8;

    // Wait, not DropWrite: DropWrite makes TryWrite answer true for the item it throws away, so a
    // full queue dropped requests without a single line saying so. Nothing here ever waits to write.
    private readonly Channel<Func<IServiceProvider, CancellationToken, Task>> _work =
        Channel.CreateBounded<Func<IServiceProvider, CancellationToken, Task>>(
            new BoundedChannelOptions(Capacity) { FullMode = BoundedChannelFullMode.Wait });

    private int _pending;

    /// <summary>How long one job may run. Well past any SMTP conversation that is going to finish;
    /// settable only so a test does not wait two minutes to watch it.</summary>
    internal TimeSpan JobTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Queues work that runs in a scope of its own, since the request's scope is gone by
    /// the time it starts.</summary>
    /// <returns>False when the queue was full and the work was dropped.</returns>
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

    /// <summary>Resolves once everything queued so far has run. For tests, which read what a
    /// notifier was handed straight after the response.</summary>
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
                // A deadline of its own: a notifier that never answers held its reader until shutdown,
                // and a few of them stopped the queue for everybody.
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                deadline.CancelAfter(JobTimeout);

                try
                {
                    await using var scope = scopes.CreateAsyncScope();
                    await work(scope.ServiceProvider, deadline.Token);
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested && !stoppingToken.IsCancellationRequested)
                {
                    logger.LogError("A queued reset or magic-link request was abandoned after {Timeout}; nothing was sent.", JobTimeout);
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
}
