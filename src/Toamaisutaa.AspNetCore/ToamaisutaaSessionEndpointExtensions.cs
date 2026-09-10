using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaSessionEndpointExtensions
{
    /// <summary>
    /// Maps the session list and the two revoke endpoints under <c>LocalLogin:EndpointPrefix</c> +
    /// <c>LocalLogin:SessionEndpointPrefix</c>. A session a user cannot see or end is the same
    /// liability a trusted device they cannot revoke is.
    /// </summary>
    /// <remarks>
    /// A session here is a refresh family - what <c>toa_sid</c> names - so it survives rotation and
    /// one entry is one sign-in rather than one access token.
    /// </remarks>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name, so the same endpoints can be mapped into more than one
    /// group. Endpoint names are unique per application, so a second group needs distinct ones.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaSessionEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix + options.SessionEndpointPrefix).WithTags("Sessions");

        // All three resolve the caller, so all three can meet a token whose stamp has moved.
        group.AddEndpointFilter<StaleSecurityStampFilter>();

        group.MapGet("/", ListAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaSessions")
            .WithSummary("Lists the sessions this user has open.")
            .WithDescription(
                "One entry per refresh family, which is what `toa_sid` names - so a session here "
                + "survives every rotation. The caller's own comes back with `isCurrent` true, "
                + "unless their token was issued by an identity provider rather than by this "
                + "application, in which case no entry is current.")
            .Produces<IReadOnlyList<SessionSummary>>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapDelete("/{sessionId:guid}", RevokeAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaRevokeSession")
            .WithSummary("Revokes one session by its id.")
            .WithDescription(
                "404 covers both a session that does not exist and one belonging to someone else, "
                + "so this cannot be used to discover another account's session ids. Revoking the "
                + "caller's own is allowed and is exactly a sign-out.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapDelete("/", RevokeAllAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaRevokeOtherSessions")
            .WithSummary("Signs out everywhere else, keeping the calling session.")
            .WithDescription(
                "Every other session ends; the refresh token the caller is holding keeps working. "
                + "A caller whose token carries no `toa_sid` has no session to keep, so every one "
                + "of them is revoked.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        return group;
    }

    private static async Task<IResult> ListAsync(
        HttpContext context,
        ICurrentUser currentUser,
        ISessionService sessions,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        return Results.Ok(await sessions.ListAsync(user.Id, CurrentSession(context), cancellationToken));
    }

    private static async Task<IResult> RevokeAsync(
        Guid sessionId,
        ICurrentUser currentUser,
        ISessionService sessions,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        return await sessions.RevokeAsync(user.Id, sessionId, cancellationToken)
            ? Results.NoContent()
            : Results.NotFound();
    }

    private static async Task<IResult> RevokeAllAsync(
        HttpContext context,
        ICurrentUser currentUser,
        ISessionService sessions,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        await sessions.RevokeAllExceptAsync(user.Id, CurrentSession(context), cancellationToken);

        return Results.NoContent();
    }

    /// <summary>
    /// Reads <c>toa_sid</c>. Absent means the caller holds a token this package did not issue - an
    /// identity provider's, most likely - so there is no session of theirs to mark or to spare.
    /// </summary>
    /// <remarks>
    /// Not the 400 that step-up answers: elevating a session that does not exist is meaningless,
    /// whereas listing and ending the local sessions of a user signed in through a provider is a
    /// perfectly ordinary thing to want.
    /// </remarks>
    private static Guid? CurrentSession(HttpContext context) =>
        Guid.TryParse(context.User.FindFirst(ToamaisutaaDefaults.SessionIdClaim)?.Value, out var sessionId)
            ? sessionId
            : null;
}
