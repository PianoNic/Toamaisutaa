using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Endpoint metadata routing turns into the request's body limit, so the server refuses an oversized
/// body before it is read, let alone bound or hashed.
/// </summary>
internal sealed class RequestBodyLimit(long maxRequestBodySize) : IRequestSizeLimitMetadata
{
    public long? MaxRequestBodySize { get; } = maxRequestBodySize;

    internal static RequestBodyLimit For(IServiceProvider services) =>
        new(services.GetService<IOptions<ToamaisutaaLocalLoginOptions>>()?.Value.MaxRequestBodyBytes
            ?? new ToamaisutaaLocalLoginOptions().MaxRequestBodyBytes);
}
