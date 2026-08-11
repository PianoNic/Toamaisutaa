using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaTwoFactorEndpointExtensions
{
    /// <summary>
    /// Maps the two-factor endpoints under <c>LocalLogin:EndpointPrefix</c> + <c>/2fa</c>.
    /// </summary>
    /// <remarks>
    /// <c>/verify</c> is anonymous because the caller has no token yet - the challenge is the
    /// credential - and it is throttled by the same limiter as <c>/login</c>. <c>/begin</c> is
    /// throttled too, for a different reason: every call writes a fresh unconfirmed secret, so an
    /// unbounded loop is write amplification rather than a guessing attack.
    /// </remarks>
    public static IEndpointConventionBuilder MapToamaisutaaTwoFactorEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix + "/2fa");

        group.MapGet("/", StatusAsync)
            .RequireAuthorization()
            .WithName("ToamaisutaaTwoFactorStatus");

        group.MapPost("/begin", BeginAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaTwoFactorBegin");

        group.MapPost("/confirm", ConfirmAsync)
            .RequireAuthorization()
            .WithName("ToamaisutaaTwoFactorConfirm");

        group.MapPost("/disable", DisableAsync)
            .RequireAuthorization()
            .WithName("ToamaisutaaTwoFactorDisable");

        group.MapPost("/recovery-codes", RegenerateAsync)
            .RequireAuthorization()
            .WithName("ToamaisutaaTwoFactorRecoveryCodes");

        group.MapPost("/verify", VerifyAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaTwoFactorVerify");

        return group;
    }

    private static async Task<IResult> StatusAsync(
        ICurrentUser currentUser,
        ITwoFactorService twoFactor,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        return Results.Ok(await twoFactor.GetStatusAsync(user.Id, cancellationToken));
    }

    /// <summary>
    /// The one endpoint in this package that returns a long-lived secret in a response body. It has
    /// to - an authenticator cannot be enrolled without being given the secret - which is exactly
    /// why nothing here or downstream ever logs what it returned.
    /// </summary>
    private static async Task<IResult> BeginAsync(
        ICurrentUser currentUser,
        ITwoFactorService twoFactor,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        try
        {
            var started = await twoFactor.BeginEnrolmentAsync(user.Id, cancellationToken);
            return Results.Ok(started);
        }
        catch (TwoFactorEnrolmentException exception)
        {
            return Results.BadRequest(new { errors = new[] { exception.Message } });
        }
    }

    private static async Task<IResult> ConfirmAsync(
        ConfirmTwoFactorRequest request,
        ICurrentUser currentUser,
        ITwoFactorService twoFactor,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Code))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        try
        {
            var completed = await twoFactor.ConfirmEnrolmentAsync(user.Id, request.Code, cancellationToken);
            return Results.Ok(completed);
        }
        catch (TwoFactorEnrolmentException exception)
        {
            return Results.BadRequest(new { errors = new[] { exception.Message } });
        }
    }

    private static async Task<IResult> DisableAsync(
        DisableTwoFactorRequest request,
        ICurrentUser currentUser,
        ITwoFactorService twoFactor,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Proof))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        var result = await twoFactor.DisableAsync(user.Id, request.Proof, cancellationToken);

        return result.Succeeded ? Results.NoContent() : Results.BadRequest(new { errors = result.Errors });
    }

    private static async Task<IResult> RegenerateAsync(
        RegenerateRecoveryCodesRequest request,
        ICurrentUser currentUser,
        ITwoFactorService twoFactor,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Proof))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        try
        {
            var completed = await twoFactor.RegenerateRecoveryCodesAsync(user.Id, request.Proof, cancellationToken);
            return Results.Ok(completed);
        }
        catch (TwoFactorEnrolmentException exception)
        {
            return Results.BadRequest(new { errors = new[] { exception.Message } });
        }
    }

    private static async Task<IResult> VerifyAsync(
        VerifyTwoFactorRequest request,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Code))
            return Unauthorized();

        var result = await signIn.VerifyTwoFactorAsync(request.Challenge, request.Code, cancellationToken);

        if (!result.Succeeded)
            return Unauthorized();

        // The one thing this response says beyond the tokens. Somebody who just spent their
        // second-to-last recovery code should find that out now, not when the last one is gone.
        return result.RecoveryCodesRunningLow
            ? Results.Ok(new
            {
                access_token = result.Tokens!.AccessToken,
                refresh_token = result.Tokens.RefreshToken,
                expires_in = result.Tokens.ExpiresIn,
                token_type = result.Tokens.TokenType,
                recovery_codes_running_low = true,
            })
            : Results.Ok(result.Tokens);
    }

    /// <summary>
    /// One body for a wrong code, an expired challenge, a spent one and an unknown one. They are the
    /// same answer to whoever is holding it, and telling them apart would say whether the challenge
    /// was ever real.
    /// </summary>
    private static IResult Unauthorized() =>
        Results.Json(
            new { error = "invalid_grant", error_description = "That code is not valid." },
            statusCode: StatusCodes.Status401Unauthorized);
}
