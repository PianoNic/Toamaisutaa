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
    /// Maps the device list and the two revoke endpoints under
    /// <c>TrustedDevices:EndpointPrefix</c>. A trust the user cannot see or take back is a
    /// liability, so these are not optional alongside the feature.
    /// </summary>
    public static IEndpointConventionBuilder MapToamaisutaaTrustedDeviceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaTrustedDeviceOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix);

        group.MapGet("/", ListAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaTrustedDevices");

        group.MapDelete("/{id:guid}", RevokeAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaRevokeTrustedDevice");

        group.MapDelete("/", RevokeAllAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaRevokeAllTrustedDevices");

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
