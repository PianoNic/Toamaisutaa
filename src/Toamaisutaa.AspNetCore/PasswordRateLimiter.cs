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
/// A fixed window per caller address, enforced inside the endpoints themselves.
/// </summary>
/// <remarks>
/// <para>
/// Lockout counts against the account, so it does nothing about someone posting a different user
/// name every time - and every one of those attempts costs a full key derivation, because an unknown
/// identifier is deliberately made to cost the same as a real one. Without a limit, that pair is an
/// unauthenticated way to spend the server's CPU.
/// </para>
/// <para>
/// Deliberately not the framework's <c>RequireRateLimiting</c>. That is metadata, inert unless the
/// application also calls <c>UseRateLimiter()</c>, and <c>UseRateLimiter</c> leaves no marker in
/// <c>app.Properties</c> to assert on - so a consumer who forgets it gets unthrottled anonymous
/// endpoints with nothing to warn them. Owning the limiter means this works because it is
/// registered, not because someone read the documentation. The cost is the framework's configured
/// rejection handling, and its metrics - which this package publishes itself instead, as
/// <c>toamaisutaa.rate_limit.rejections</c>.
/// </para>
/// </remarks>
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

            // Behind a proxy this is the proxy unless the application has configured forwarded
            // headers, which is its call to make rather than ours to guess - but it can be noticed.
            // The forwarded-headers middleware consumes X-Forwarded-For as it rewrites the address,
            // so the header still being here, on a connection from a private or loopback address,
            // means nobody configured it and every caller is sharing one budget.
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

            var partition = PartitionKey(remote, settings.Nat64Prefixes);

            return RateLimitPartition.GetFixedWindowLimiter(
                partition,
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
    /// One budget per caller. An IPv6 caller is its /64, because that is what one customer is
    /// handed: keyed on the full address, every one of the 2^64 addresses in it was a fresh budget.
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

        // A NAT64 gateway puts every IPv4 client it translates in one /64, so one of them sending a
        // few wrong passwords used to cost all the others their budget. The IPv4 address is inside,
        // where RFC 6052 puts it for the prefix's length.
        foreach (var prefix in WellKnownNat64.Concat(ParseNat64Prefixes(nat64Prefixes)))
        {
            if (prefix.Contains(address))
                return new IPAddress(EmbeddedIpv4(bytes, prefix.PrefixLength)).ToString();
        }

        Array.Clear(bytes, 8, 8);

        return $"{new IPAddress(bytes)}/64";
    }

    private static readonly IPNetwork[] WellKnownNat64 = [IPNetwork.Parse("64:ff9b::/96"), IPNetwork.Parse("64:ff9b:1::/48")];

    // One that does not parse is skipped here; the startup check refuses it, so it is never skipped
    // silently.
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

/// <summary>Turns a refused lease into 429 without touching any other endpoint's behaviour.</summary>
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
