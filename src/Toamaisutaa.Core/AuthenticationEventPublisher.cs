using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Sinks are resolved lazily inside the publisher's try block, so a sink whose constructor throws
/// cannot fail the request the way injecting an <c>IEnumerable</c> of sinks would.
/// </summary>
internal sealed record AuthenticationEventSinkRegistration(Type SinkType, Func<IAuthenticationEventSink> Resolve);

internal sealed class AuthenticationEventPublisher(
    IEnumerable<AuthenticationEventSinkRegistration> sinks,
    ILogger<AuthenticationEventPublisher> logger)
{
    internal async Task PublishAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken)
    {
        foreach (var registration in sinks)
        {
            try
            {
                await registration.Resolve().HandleAsync(authenticationEvent, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // A failing sink must not turn a correct sign-in into a 500. Cancellation only
                // propagates when this request was cancelled: HttpClient and database timeouts also
                // raise TaskCanceledException.
                logger.LogError(
                    ex,
                    "Authentication event sink {Sink} failed handling {Kind} for user {UserId}. The event is lost; the request is not affected.",
                    registration.SinkType.FullName,
                    authenticationEvent.Kind,
                    authenticationEvent.UserId);
            }
        }
    }
}
