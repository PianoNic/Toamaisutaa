using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Turns a stale security stamp into 401, and a disabled account into 403, rather than a 500, which
/// the happy path of enrolment and password changes otherwise reaches; a filter so the package's
/// endpoints need no consumer setup.
/// </summary>
internal sealed class StaleSecurityStampFilter(ILogger<StaleSecurityStampFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (SecurityStampChangedException)
        {
            logger.LogInformation(
                "Request refused: the token's security stamp is stale, so a credential changed after it was issued.");

            return StaleSecurityStamp(context.HttpContext);
        }
        catch (AccountDisabledException)
        {
            logger.LogInformation("Request refused: the account is disabled.");

            return AccountDisabled();
        }
    }

    /// <summary>403, not 401: the token is valid, and a client that refreshed on 401 would only be refused again.</summary>
    internal static IResult AccountDisabled() =>
        Results.Json(
            new ErrorResponse { Error = "account_disabled", ErrorDescription = "This account is disabled." },
            statusCode: StatusCodes.Status403Forbidden);

    /// <summary>
    /// RFC 6750 <c>invalid_token</c> in <c>WWW-Authenticate</c>, which client libraries read to decide
    /// whether to refresh.
    /// </summary>
    internal static IResult StaleSecurityStamp(HttpContext context)
    {
        const string description = "This token was issued before a credential on the account changed. Refresh, or sign in again.";

        context.Response.Headers.WWWAuthenticate =
            $"Bearer error=\"invalid_token\", error_description=\"{description}\"";

        return Results.Json(
            new ErrorResponse { Error = "invalid_token", ErrorDescription = description },
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
