using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

/// <summary>
/// Holds one discovery answer for a bounded interval, so how often this process asks the issuer for
/// its metadata is not decided by whoever is reading the document.
/// </summary>
/// <remarks>
/// <para>
/// The document transformer runs on every request to <c>/openapi/v1.json</c>, and that route is
/// anonymous wherever it is mapped at all. Without this, an unauthenticated caller in a loop sets
/// the rate of outbound requests to the identity provider, from a source the issuer's own rate
/// limiting sees as one trusted service. The discovery health check keeps its last result for the
/// same reason and for the same five minutes.
/// </para>
/// <para>
/// A failed discovery is held too. The alternative is that an issuer outage makes every request for
/// the document wait the full discovery timeout, which turns one unreachable issuer into a slow
/// route; the cost is that the <c>OAuth2</c> scheme can stay out of the document for up to the
/// interval after the issuer comes back, and the <c>Bearer</c> scheme carries the document in the
/// meantime.
/// </para>
/// </remarks>
internal sealed class AuthorizationServerMetadataCache
{
    /// <summary>How long an answer is trusted. The discovery health check's own default, for a
    /// document that changes when the issuer is redeployed and not otherwise.</summary>
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

        // The load this exists to bound arrives in parallel, so concurrent readers wait on one fetch
        // rather than each starting their own.
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
