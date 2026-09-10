using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

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
    IEnumerable<IAuthenticationEventSink> sinks,
    ILogger<AuthenticationEventPublisher> logger)
{
    internal async Task PublishAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken)
    {
        foreach (var sink in sinks)
        {
            try
            {
                await sink.HandleAsync(authenticationEvent, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // An audit sink is a consumer's code talking to a consumer's storage, and it can
                // fail for reasons that have nothing to do with the account: an outage, a schema
                // that moved, a bad connection string. None of that may turn a correct sign-in into
                // a 500 - so it is logged here, where the request is still identifiable, and gone.
                logger.LogError(
                    ex,
                    "Authentication event sink {Sink} failed handling {Kind} for user {UserId}. The event is lost; the request is not affected.",
                    sink.GetType().FullName,
                    authenticationEvent.Kind,
                    authenticationEvent.UserId);
            }
        }
    }
}
