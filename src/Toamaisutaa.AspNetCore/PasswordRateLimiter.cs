using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Owned here rather than the framework's <c>RequireRateLimiting</c>, which is silently inert unless the
/// application also calls <c>UseRateLimiter()</c> and would leave the key-derivation endpoints unthrottled.
/// </summary>
internal sealed class PasswordRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<HttpContext> _limiter;

    private int _warnedAboutProxy;

    public PasswordRateLimiter(IOptions<ToamaisutaaLocalLoginOptions> options, ILogger<PasswordRateLimiter> logger)
    {
        _limiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            var settings = options.Value.RateLimit;

            if (!settings.Enabled)
                return RateLimitPartition.GetNoLimiter("disabled");

            // The forwarded-headers middleware consumes X-Forwarded-For, so seeing it from a private
            // address means nobody configured it and every caller shares the proxy's budget.
            var remote = context.Connection.RemoteIpAddress;

            if (remote is not null
                && context.Request.Headers.ContainsKey("X-Forwarded-For")
                && IsPrivateOrLoopback(remote)
                && Interlocked.Exchange(ref _warnedAboutProxy, 1) == 0)
            {
                logger.LogWarning(
                    "Rate limiting is keyed on the caller's address, but requests arrive from {ProxyAddress} with an "
                    + "unprocessed X-Forwarded-For header: every client behind that proxy shares one limit. Configure "
                    + "ForwardedHeadersOptions and call UseForwardedHeaders() before the endpoints.",
                    remote);
            }

            return RateLimitPartition.GetFixedWindowLimiter(
                PartitionKey(remote, settings.Nat64Prefixes),
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = settings.PermitLimit,
                    Window = settings.Window,
                    QueueLimit = 0,
                });
        });
    }

    public ValueTask<RateLimitLease> AcquireAsync(HttpContext context) => _limiter.AcquireAsync(context);

    /// <summary>
    /// An IPv6 caller is keyed by its /64, since one customer is handed the whole /64.
    /// </summary>
    internal static string PartitionKey(IPAddress? address, IEnumerable<string>? nat64Prefixes = null)
    {
        if (address is null)
            return "unknown";

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return address.ToString();

        var bytes = address.GetAddressBytes();

        // A NAT64 gateway puts every IPv4 client in one /64, so key on the embedded IPv4 address instead.
        foreach (var prefix in WellKnownNat64.Concat(ParseNat64Prefixes(nat64Prefixes)))
        {
            if (prefix.Contains(address))
                return new IPAddress(EmbeddedIpv4(bytes, prefix.PrefixLength)).ToString();
        }

        Array.Clear(bytes, 8, 8);

        return $"{new IPAddress(bytes)}/64";
    }

    private static readonly IPNetwork[] WellKnownNat64 = [IPNetwork.Parse("64:ff9b::/96"), IPNetwork.Parse("64:ff9b:1::/48")];

    // Skipping an unparsable prefix is safe only because the startup check refuses it.
    private static IEnumerable<IPNetwork> ParseNat64Prefixes(IEnumerable<string>? values)
    {
        foreach (var value in values ?? [])
        {
            if (Nat64Prefix.TryParse(value, out var prefix))
                yield return prefix;
        }
    }

    /// <summary>RFC 6052 section 2.2: the four octets follow the prefix, skipping octet 8, which is
    /// reserved and always zero.</summary>
    private static byte[] EmbeddedIpv4(byte[] address, int prefixLength)
    {
        var ipv4 = new byte[4];
        var at = prefixLength / 8;

        for (var i = 0; i < 4; i++, at++)
        {
            if (at == 8)
                at++;

            ipv4[i] = address[at];
        }

        return ipv4;
    }

    private static bool IsPrivateOrLoopback(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return true;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6UniqueLocal || address.IsIPv6LinkLocal;

        var bytes = address.GetAddressBytes();

        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168);
    }

    public void Dispose() => _limiter.Dispose();
}

internal sealed class PasswordRateLimitFilter(PasswordRateLimiter limiter, ToamaisutaaMetrics metrics) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        using var lease = await limiter.AcquireAsync(context.HttpContext);

        if (lease.IsAcquired)
            return await next(context);

        metrics.RateLimitRejected();
        return Results.StatusCode(StatusCodes.Status429TooManyRequests);
    }
}
