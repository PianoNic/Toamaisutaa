using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

internal sealed class FakeLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add((logLevel, formatter(state, exception)));
    }
}

internal sealed class FakeInnerValidator(params string[] errors) : IPasswordValidator
{
    public List<string> Seen { get; } = [];

    public IReadOnlyList<string> Validate(string password)
    {
        Seen.Add(password);
        return errors;
    }
}

internal sealed class ScopedDependency
{
    public string Id { get; } = Guid.NewGuid().ToString();
}

internal sealed class DisposalLog
{
    public List<string> Disposed { get; } = [];
}

/// <summary>Its one error names its scoped dependency, so a captured instance is visible.</summary>
internal sealed class ScopedInnerValidator(ScopedDependency dependency, DisposalLog log) : IPasswordValidator, IDisposable
{
    public IReadOnlyList<string> Validate(string password) => [dependency.Id];

    public void Dispose() => log.Disposed.Add(dependency.Id);
}

internal sealed class FakeBreachedPasswordIndex(int count, Exception? throws = null) : IBreachedPasswordIndex
{
    public List<string> Asked { get; } = [];

    public ValueTask<int> CountAsync(string password, CancellationToken cancellationToken = default)
    {
        Asked.Add(password);

        return throws is null
            ? ValueTask.FromResult(count)
            : ValueTask.FromException<int>(throws);
    }
}

internal sealed class RecordingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];

    public static RecordingHandler Answering(string body) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(body),
        }));

    public static RecordingHandler Failing(Exception exception) =>
        new((_, _) => Task.FromException<HttpResponseMessage>(exception));

    public static RecordingHandler Hanging() =>
        new(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new System.Diagnostics.UnreachableException();
        });

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return respond(request, cancellationToken);
    }
}

internal sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public List<string> Named { get; } = [];

    public HttpClient CreateClient(string name)
    {
        Named.Add(name);
        return new HttpClient(handler, disposeHandler: false);
    }
}
