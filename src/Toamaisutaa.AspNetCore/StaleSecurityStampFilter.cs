using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Turns a stale security stamp into 401 instead of letting it escape as an unhandled exception.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ICurrentUser.GetOrProvisionAsync"/> throws
/// <see cref="SecurityStampChangedException"/> when a token was issued before a credential changed.
/// That is an authentication failure and always was; nothing mapped it, so it surfaced as a 500 -
/// a stack trace in Development and a bare server error in Production, for a token the client only
/// needed to refresh.
/// </para>
/// <para>
/// It is reachable from the happy path rather than an edge: confirming a two-factor enrolment moves
/// the stamp, so the token that made the call is dead the moment it returns, and the next request
/// was answering 500. Disabling two-factor, regenerating recovery codes, changing a password and
/// resetting one all do the same.
/// </para>
/// <para>
/// A filter rather than middleware, so the package's own endpoints are correct without a consumer
/// having to remember anything. Endpoints of your own that call
/// <see cref="ICurrentUser.GetOrProvisionAsync"/> need the same treatment - see the docs for an
/// <c>IExceptionHandler</c> that covers the whole application.
/// </para>
/// </remarks>
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
    }

    /// <summary>
    /// RFC 6750 names this case <c>invalid_token</c> and asks for the reason in
    /// <c>WWW-Authenticate</c>, which is what a client library looks at before it decides whether
    /// refreshing is worth trying.
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
