using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaPasswordEndpointExtensions
{
    /// <summary>
    /// Maps the local sign-in endpoints under <c>LocalLogin:EndpointPrefix</c>.
    /// </summary>
    /// <remarks>
    /// The anonymous endpoints throttle themselves through a limiter this package owns, so there is
    /// no middleware for a consumer to remember to add.
    /// </remarks>
    public static IEndpointConventionBuilder MapToamaisutaaPasswordEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix);

        group.MapPost("/login", LoginAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaLogin");

        group.MapPost("/refresh", RefreshAsync)
            .AllowAnonymous()
            .WithName("ToamaisutaaRefresh");

        group.MapPost("/logout", LogoutAsync)
            .AllowAnonymous()
            .WithName("ToamaisutaaLogout");

        // Not mapped at all when self-registration is off, rather than mapped and answering 403.
        if (options.AllowSelfRegistration)
        {
            group.MapPost("/register", RegisterAsync)
                .AllowAnonymous()
                .AddEndpointFilter<PasswordRateLimitFilter>()
                .WithName("ToamaisutaaRegister");
        }

        // Explicitly authorised rather than relying on the fallback policy, which an application is
        // free to turn off.
        group.MapPost("/password", ChangePasswordAsync)
            .RequireAuthorization()
            .WithName("ToamaisutaaChangePassword");

        group.MapPost("/password/forgot", ForgotPasswordAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName("ToamaisutaaForgotPassword");

        group.MapPost("/password/reset", ResetPasswordAsync)
            .AllowAnonymous()
            .WithName("ToamaisutaaResetPassword");

        return group;
    }

    /// <summary>
    /// One body for every way a sign-in can fail. Wrong password, no such account and locked out are
    /// the same answer, because telling them apart tells a caller which user names are real.
    /// </summary>
    private static IResult SignInFailed() =>
        Results.Json(
            new { error = "invalid_grant", error_description = "The credentials are not valid." },
            statusCode: StatusCodes.Status401Unauthorized);

    private static async Task<IResult> LoginAsync(
        LoginRequest request,
        HttpContext context,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Identifier) || string.IsNullOrEmpty(request.Password))
            return SignInFailed();

        var result = await signIn.SignInAsync(
            new PasswordSignInRequest
            {
                Identifier = request.Identifier,
                Password = request.Password,
                DeviceToken = request.DeviceToken,
                UserAgent = context.Request.Headers.UserAgent.ToString(),
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            },
            cancellationToken);

        // A second shape on the success path, not a new status code: the password was right, and
        // what comes back is what to do next rather than an error. Clients that assumed tokens do
        // have to change, which is why this is a breaking release.
        if (result.Outcome == SignInOutcome.TwoFactorRequired && result.Challenge is { } challenge)
        {
            return Results.Ok(new
            {
                two_factor_required = true,
                challenge = challenge.Token,
                expires_in = challenge.ExpiresIn,
            });
        }

        return result.Succeeded ? SignInSucceeded(result) : SignInFailed();
    }

    /// <summary>
    /// The one place a successful sign-in is shaped, shared by <c>/auth/login</c>,
    /// <c>/auth/refresh</c>, <c>/auth/register</c> and <c>/auth/2fa/verify</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Shared because it was not, and the device token this returns went missing: a device-trusted
    /// sign-in rotates the token, and an endpoint that returned only the token pair left the caller
    /// holding a dead one. The next sign-in then presented an already-rotated token, which is the
    /// theft signal, and the family was revoked. One use and the device silently stopped working.
    /// </para>
    /// <para>
    /// <b>snake_case, deliberately.</b> These are the RFC 6749 field names - <c>access_token</c>,
    /// <c>token_type</c>, <c>expires_in</c> - so anything that already speaks OAuth token endpoints
    /// reads this without a mapping. Endpoints that return this package's own shapes
    /// (<c>/auth/2fa</c>, <c>/auth/devices</c>) stay camelCase, because they are not token responses
    /// and no standard names them.
    /// </para>
    /// </remarks>
    internal static IResult SignInSucceeded(SignInResult result) =>
        TokenResponse(result.Tokens!, result.RecoveryCodesRunningLow, result.TrustedDevice, StatusCodes.Status200OK);

    internal static IResult TokenResponse(
        TokenPair tokens,
        bool recoveryCodesRunningLow,
        TrustedDeviceToken? trustedDevice,
        int statusCode) =>
        Results.Json(
            new
            {
                access_token = tokens.AccessToken,
                refresh_token = tokens.RefreshToken,
                expires_in = tokens.ExpiresIn,
                token_type = tokens.TokenType,
                recovery_codes_running_low = recoveryCodesRunningLow ? true : (bool?)null,
                device_token = trustedDevice?.Token,
                device_expires_in = trustedDevice?.ExpiresIn,
            },
            statusCode: statusCode);

    private static async Task<IResult> RefreshAsync(
        RefreshRequest request,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.RefreshToken))
            return SignInFailed();

        var result = await signIn.RefreshAsync(request.RefreshToken, cancellationToken);

        return result.Succeeded ? SignInSucceeded(result) : SignInFailed();
    }

    private static async Task<IResult> LogoutAsync(
        LogoutRequest request,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is not null && !string.IsNullOrEmpty(request.RefreshToken))
            await signIn.SignOutAsync(request.RefreshToken, cancellationToken);

        // Always the same answer: whether that token existed is not the caller's business.
        return Results.NoContent();
    }

    private static async Task<IResult> RegisterAsync(
        RegisterRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null)
            return Results.BadRequest();

        var result = await accounts.RegisterAsync(request, cancellationToken);

        if (result.Succeeded)
            return TokenResponse(result.Tokens!, false, null, StatusCodes.Status201Created);

        // Registration cannot hide whether an account exists without an email round trip, which
        // this package does not do. Documented, and why it is off by default.
        return result.Conflict
            ? Results.Json(new { errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
            : Results.BadRequest(new { errors = result.Errors });
    }

    private static async Task<IResult> ChangePasswordAsync(
        ChangePasswordRequest request,
        ICurrentUser currentUser,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.NewPassword))
            return Results.BadRequest();

        // Resolves the local row for whoever is calling, including a caller holding an identity
        // provider's token who is adding a password to their account for the first time.
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        var result = await accounts.SetPasswordAsync(user.Id, request.CurrentPassword, request.NewPassword, cancellationToken);

        return result.Succeeded ? Results.NoContent() : Results.BadRequest(new { errors = result.Errors });
    }

    private static async Task<IResult> ForgotPasswordAsync(
        ForgotPasswordRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is not null && !string.IsNullOrEmpty(request.Email))
            await accounts.RequestPasswordResetAsync(request.Email, cancellationToken);

        // Unknown address, no local credential, and a link on its way are one answer. The log tells
        // them apart.
        return Results.NoContent();
    }

    private static async Task<IResult> ResetPasswordAsync(
        ResetPasswordRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Token) || string.IsNullOrEmpty(request.NewPassword))
            return Results.BadRequest();

        var result = await accounts.ResetPasswordAsync(request.Token, request.NewPassword, cancellationToken);

        return result.Succeeded ? Results.NoContent() : Results.BadRequest(new { errors = result.Errors });
    }
}
