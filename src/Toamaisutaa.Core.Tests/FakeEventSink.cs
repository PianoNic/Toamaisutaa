using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

internal sealed class RecordingEventSink : IAuthenticationEventSink
{
    internal List<AuthenticationEvent> Events { get; } = [];

    public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
    {
        Events.Add(authenticationEvent);
        return Task.CompletedTask;
    }

    internal IReadOnlyList<T> OfKind<T>() where T : AuthenticationEvent => [.. Events.OfType<T>()];

    internal T Single<T>() where T : AuthenticationEvent => OfKind<T>().Single();
}

internal sealed class ThrowingEventSink : IAuthenticationEventSink
{
    public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("the audit database is unreachable");
}
