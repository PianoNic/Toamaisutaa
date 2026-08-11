using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// A fixed window per caller address on the anonymous password endpoints.
/// </summary>
/// <remarks>
/// Lockout counts against the account, so it does nothing about someone posting a different user
/// name every time - and every one of those attempts costs a full key derivation, because an
/// unknown identifier is deliberately made to cost the same as a real one. Without a limit, that
/// pair is an unauthenticated way to spend the server's CPU.
/// <para>
/// Written as a policy rather than by configuring the global rate limiter, so that answering 429
/// here does not change the rejection status code of any other policy the application has.
/// </para>
/// </remarks>
internal sealed class PasswordEndpointRateLimiterPolicy(IOptions<ToamaisutaaLocalLoginOptions> options)
    : IRateLimiterPolicy<string>
{
    public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected => (context, _) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        return ValueTask.CompletedTask;
    };

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        var settings = options.Value.RateLimit;

        if (!settings.Enabled)
            return RateLimitPartition.GetNoLimiter("disabled");

        // Behind a proxy this is the proxy unless the application has configured forwarded headers,
        // which is its call to make rather than ours to guess.
        var partition = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        return RateLimitPartition.GetFixedWindowLimiter(
            partition,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = settings.PermitLimit,
                Window = settings.Window,
                QueueLimit = 0,
            });
    }
}
