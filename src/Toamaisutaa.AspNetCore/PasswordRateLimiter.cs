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
    private readonly PartitionedRateLimiter<HttpContext> _callers;
    private readonly PartitionedRateLimiter<HttpContext> _sites;

    private int _warnedAboutProxy;

    public PasswordRateLimiter(IOptions<ToamaisutaaLocalLoginOptions> options, ILogger<PasswordRateLimiter> logger)
    {
        _callers = PartitionedRateLimiter.Create<HttpContext, string>(context =>
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

        // Chained, so a caller spends from its own budget and its /48's at once.
        _sites = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            var settings = options.Value.RateLimit;

            return settings.Enabled && SiteKey(context.Connection.RemoteIpAddress, settings.Nat64Prefixes) is { } site
                ? RateLimitPartition.GetFixedWindowLimiter(
                    site,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = settings.Ipv6SitePermitLimit,
                        Window = settings.Window,
                        QueueLimit = 0,
                    })
                : RateLimitPartition.GetNoLimiter("no-site");
        });

        _limiter = PartitionedRateLimiter.CreateChained(_callers, _sites);
    }

    /// <summary>The /48 of a native IPv6 caller; null for IPv4 and NAT64, which are keyed on one address.</summary>
    internal static string? SiteKey(IPAddress? address, IEnumerable<string>? nat64Prefixes = null)
    {
        if (address is null || address.IsIPv4MappedToIPv6 || address.AddressFamily != AddressFamily.InterNetworkV6
            || Nat64Match(address, nat64Prefixes) is not null)
            return null;

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 6, 10);

        return $"{new IPAddress(bytes)}/48";
    }

    public ValueTask<RateLimitLease> AcquireAsync(HttpContext context) => _limiter.AcquireAsync(context);

    /// <summary>
    /// An IPv6 caller is keyed by its /64, the smallest network a customer is handed; its /48 is limited
    /// as well, by <see cref="SiteKey"/>.
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
        if (Nat64Match(address, nat64Prefixes) is { } nat64)
            return new IPAddress(EmbeddedIpv4(bytes, nat64.PrefixLength)).ToString();

        Array.Clear(bytes, 8, 8);

        return $"{new IPAddress(bytes)}/64";
    }

    // Longest match wins: an operator's /96 carved from the well-known /48 embeds the client after its
    // own prefix, where the /48 layout reads only zeros.
    private static IPNetwork? Nat64Match(IPAddress address, IEnumerable<string>? nat64Prefixes) =>
        WellKnownNat64.Concat(ParseNat64Prefixes(nat64Prefixes))
            .Where(prefix => prefix.Contains(address))
            .OrderByDescending(prefix => prefix.PrefixLength)
            .Cast<IPNetwork?>()
            .FirstOrDefault();

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

    // A chained limiter does not dispose the ones it wraps.
    public void Dispose()
    {
        _limiter.Dispose();
        _callers.Dispose();
        _sites.Dispose();
    }
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
