using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

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
/// Bounded, and a full queue drops the request rather than growing. Whoever is filling it faster
/// than mail can be sent is not somebody waiting on a link.
/// </para>
/// </remarks>
internal sealed class MailRequestQueue(IServiceScopeFactory scopes, ILogger<MailRequestQueue> logger) : BackgroundService
{
    private const int Capacity = 1000;

    private readonly Channel<Func<IServiceProvider, CancellationToken, Task>> _work =
        Channel.CreateBounded<Func<IServiceProvider, CancellationToken, Task>>(
            new BoundedChannelOptions(Capacity) { SingleReader = true, FullMode = BoundedChannelFullMode.DropWrite });

    private int _pending;

    /// <summary>Queues work that runs in a scope of its own, since the request's scope is gone by
    /// the time it starts.</summary>
    internal void Enqueue(Func<IServiceProvider, CancellationToken, Task> work)
    {
        Interlocked.Increment(ref _pending);

        if (_work.Writer.TryWrite(work))
            return;

        Interlocked.Decrement(ref _pending);
        logger.LogWarning("The mail request queue is full; a reset or magic-link request was dropped without being processed.");
    }

    /// <summary>Resolves once everything queued so far has run. For tests, which read what a
    /// notifier was handed straight after the response.</summary>
    internal async Task WhenIdleAsync()
    {
        while (Volatile.Read(ref _pending) > 0)
            await Task.Delay(5);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var work in _work.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await work(scope.ServiceProvider, stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(exception, "A queued reset or magic-link request failed.");
            }
            finally
            {
                Interlocked.Decrement(ref _pending);
            }
        }
    }
}
