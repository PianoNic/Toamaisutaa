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

/// <summary>Stands in for the length rules, so the validator's own decisions can be told apart from
/// theirs.</summary>
internal sealed class FakeInnerValidator(params string[] errors) : IPasswordValidator
{
    public List<string> Seen { get; } = [];

    public IReadOnlyList<string> Validate(string password)
    {
        Seen.Add(password);
        return errors;
    }
}

/// <summary>A corpus with no network behind it: a fixed answer, or a fixed failure.</summary>
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

/// <summary>Records what the range lookup actually sent, which is the only way to check that
/// nothing beyond the prefix left the process.</summary>
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
