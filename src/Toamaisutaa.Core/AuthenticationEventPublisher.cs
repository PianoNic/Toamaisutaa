using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// One registered sink, named but not yet built.
/// </summary>
/// <remarks>
/// The publisher takes these rather than the sinks themselves because dependency injection
/// materialises an <c>IEnumerable&lt;IAuthenticationEventSink&gt;</c> when the publisher is
/// resolved, which is before any request has reached a try block. A sink whose constructor throws
/// is a sink that throws, and the promise this package makes about that has no exception in it.
/// </remarks>
internal sealed record AuthenticationEventSinkRegistration(Type SinkType, Func<IAuthenticationEventSink> Resolve);

/// <summary>
/// Hands an event to every registered sink and lets none of them break the request.
/// </summary>
/// <remarks>
/// Injected as a concrete type rather than an interface because there is nothing here for a
/// consumer to replace: what is pluggable is the sink. With none registered this is the no-op the
/// sign-in path can call unconditionally, which is what keeps every call site a single line with no
/// null check in front of it.
/// </remarks>
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
                // An audit sink is a consumer's code talking to a consumer's storage, and it can
                // fail for reasons that have nothing to do with the account: an outage, a schema
                // that moved, a bad connection string. None of that may turn a correct sign-in into
                // a 500 - so it is logged here, where the request is still identifiable, and gone.
                //
                // Cancellation is only let through when this request was the thing cancelled. A
                // sink posting to an audit API raises TaskCanceledException on HttpClient's own
                // timeout, and a database command raises it on its own, neither of which is the
                // caller having gone away.
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
