using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>Keeps everything it is handed, in order, so a test can ask what the flow published.</summary>
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

/// <summary>A sink that fails the way a real one does when its storage is unreachable.</summary>
internal sealed class ThrowingEventSink : IAuthenticationEventSink
{
    public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("the audit database is unreachable");
}
