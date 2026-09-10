using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
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

    public PasswordRateLimiter(IOptions<ToamaisutaaLocalLoginOptions> options)
    {
        _limiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            var settings = options.Value.RateLimit;

            if (!settings.Enabled)
                return RateLimitPartition.GetNoLimiter("disabled");

            // Behind a proxy this is the proxy unless the application has configured forwarded
            // headers, which is its call to make rather than ours to guess.
            var partition = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

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
