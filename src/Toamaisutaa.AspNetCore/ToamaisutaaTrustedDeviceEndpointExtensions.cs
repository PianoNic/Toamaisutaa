using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Core;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaTrustedDeviceEndpointExtensions
{
    /// <summary>
    /// Maps the device list and the two revoke endpoints under <c>LocalLogin:EndpointPrefix</c> +
    /// <c>TrustedDevices:EndpointPrefix</c>. A trust the user cannot see or take back is a
    /// liability, so these are not optional alongside the feature.
    /// </summary>
    /// <remarks>
    /// The prefix composes onto the local login one, the same way <c>/2fa</c> does. It used to be a
    /// full path defaulting to <c>/auth/devices</c>, which meant moving <c>LocalLogin</c> to
    /// <c>/identity</c> moved sign-in and two-factor and silently left the devices behind.
    /// </remarks>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name, so the same endpoints can be mapped into more than one
    /// group. Endpoint names are unique per application, so a second group needs distinct ones.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaTrustedDeviceEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaTrustedDeviceOptions>>().Value;
        var localLogin = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(localLogin.EndpointPrefix + options.EndpointPrefix).WithTags("Trusted devices");

        group.MapGet("/", ListAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaTrustedDevices")
            .WithSummary("Lists the devices this user has trusted.")
            .WithDescription(
                "Send the device token you are holding in an `X-Toamaisutaa-Device` header and the "
                + "matching row comes back with `isCurrent` true, so a list can say \"this device\" "
                + "rather than inviting somebody to revoke the one they are sitting at.")
            .Produces<IReadOnlyList<TrustedDeviceSummary>>()
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapDelete("/{id:guid}", RevokeAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaRevokeTrustedDevice")
            .WithSummary("Revokes one device by its id.")
            .WithDescription(
                "404 covers both a device that does not exist and one belonging to someone else, so "
                + "this cannot be used to discover another account's device ids.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapDelete("/", RevokeAllAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaRevokeAllTrustedDevices")
            .WithSummary("Revokes every device this user has trusted.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        return group;
    }

    private static async Task<IResult> ListAsync(
        HttpContext context,
        ICurrentUser currentUser,
        ITrustedDeviceService devices,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        // A caller who sends the device token they are holding gets IsCurrent on the matching row,
        // so a UI can avoid inviting somebody to revoke the device they are sitting at. Optional,
        // and read from a header rather than the body because this is a GET.
        if (devices is TrustedDeviceService concrete
            && context.Request.Headers.TryGetValue("X-Toamaisutaa-Device", out var presented)
            && !string.IsNullOrWhiteSpace(presented))
        {
            concrete.CurrentDeviceTokenHash = SecureTokens.HashToken(presented.ToString());
        }

        return Results.Ok(await devices.ListAsync(user.Id, cancellationToken));
    }

    private static async Task<IResult> RevokeAsync(
        Guid id,
        ICurrentUser currentUser,
        ITrustedDeviceService devices,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        return await devices.RevokeAsync(user.Id, id, cancellationToken)
            ? Results.NoContent()
            : Results.NotFound();
    }

    private static async Task<IResult> RevokeAllAsync(
        ICurrentUser currentUser,
        ITrustedDeviceService devices,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        await devices.RevokeAllAsync(user.Id, cancellationToken);

        return Results.NoContent();
    }
}
