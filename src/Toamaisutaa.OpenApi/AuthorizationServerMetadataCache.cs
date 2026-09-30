using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

/// <summary>
/// The document route is anonymous, so without this cache an unauthenticated caller in a loop would
/// set the rate of outbound requests to the identity provider.
/// </summary>
/// <remarks>
/// Failures are cached too, so an issuer outage does not make every document request wait the full
/// discovery timeout.
/// </remarks>
internal sealed class AuthorizationServerMetadataCache
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly SemaphoreSlim _gate = new(1, 1);

    private volatile Answer? _last;

    public async Task<(Uri AuthorizationUrl, Uri TokenUrl)?> GetAsync(
        ToamaisutaaOidcOptions settings,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var time = services.GetService<TimeProvider>() ?? TimeProvider.System;

        if (Fresh(_last, time.GetUtcNow()) is { } cached)
            return cached.Endpoints;

        // Concurrent readers wait on one fetch rather than each starting their own.
        await _gate.WaitAsync(cancellationToken);

        try
        {
            var now = time.GetUtcNow();

            if (Fresh(_last, now) is { } filled)
                return filled.Endpoints;

            var endpoints = await AuthorizationServerMetadata.DiscoverAsync(settings, services, cancellationToken);

            _last = new Answer(now, endpoints);

            return endpoints;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static Answer? Fresh(Answer? answer, DateTimeOffset now) =>
        answer is not null && now - answer.At < Lifetime ? answer : null;

    private sealed record Answer(DateTimeOffset At, (Uri AuthorizationUrl, Uri TokenUrl)? Endpoints);
}
