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
    /// <para>
    /// The anonymous endpoints throttle themselves through a limiter this package owns, so there is
    /// no middleware for a consumer to remember to add.
    /// </para>
    /// <para>
    /// Maps into whatever builder it is handed, so <c>app.MapGroup("/api/v1")</c> nests these under
    /// that group and any conventions on it apply. <paramref name="endpointNamePrefix"/> is what
    /// makes that work more than once: endpoint names are unique per application, so mapping the
    /// same set into a second group needs distinct ones.
    /// </para>
    /// </remarks>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name, so the same endpoints can be mapped into more than one
    /// group. Pass a distinct value per group - <c>"V1"</c> gives <c>V1ToamaisutaaLogin</c>.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaPasswordEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix).WithTags("Authentication");

        // /auth/password resolves the caller, so it can meet a token whose stamp has moved.
        group.AddEndpointFilter<StaleSecurityStampFilter>();

        group.MapPost("/login", LoginAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaLogin")
            .WithSummary("Signs in with a password, or asks for a second factor.")
            // Two different bodies share the 200 here, and OpenAPI keys a response on its status
            // code, so only one schema can be declared. The token pair is declared because it is
            // the common case; the challenge is spelled out here because a client that misses the
            // branch breaks the moment any user enrols.
            .WithDescription(
                "**Two success shapes, both 200.** Usually a token pair. For a user with a "
                + "confirmed second factor it is instead a challenge and no tokens:\n\n"
                + "```json\n{ \"two_factor_required\": true, \"challenge\": \"No1CXq9-...\", \"expires_in\": 300 }\n```\n\n"
                + "Branch on `two_factor_required`, which is absent from the token shape. Present "
                + "the challenge with a code to `/auth/2fa/verify` to finish signing in.")
            .Produces<TwoFactorChallengeResponse>()
            .Produces<TokenResponse>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/refresh", RefreshAsync)
            .AllowAnonymous()
            .WithName($"{endpointNamePrefix}ToamaisutaaRefresh")
            .WithSummary("Exchanges a refresh token for a new pair, rotating it.")
            .WithDescription(
                "Presenting a token that has already been rotated revokes the whole family, and "
                + "every trusted device with it.")
            .Produces<TokenResponse>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/logout", LogoutAsync)
            .AllowAnonymous()
            .WithName($"{endpointNamePrefix}ToamaisutaaLogout")
            .WithSummary("Revokes the presented refresh token's family.")
            .WithDescription(
                "Always 204. Whether that token existed is not the caller's business. Trusted "
                + "devices are deliberately left alone - signing out is not a security event.")
            .Produces(StatusCodes.Status204NoContent);

        // Not mapped at all when self-registration is off, rather than mapped and answering 403.
        if (options.AllowSelfRegistration)
        {
            group.MapPost("/register", RegisterAsync)
                .AllowAnonymous()
                .AddEndpointFilter<PasswordRateLimitFilter>()
                .WithName($"{endpointNamePrefix}ToamaisutaaRegister")
                .WithSummary("Creates a local account and signs it in.")
                .WithDescription("Mapped only when `LocalLogin:AllowSelfRegistration` is true.")
                .Produces<TokenResponse>(StatusCodes.Status201Created)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces<ValidationErrorResponse>(StatusCodes.Status409Conflict)
                .Produces(StatusCodes.Status429TooManyRequests);
        }

        // Explicitly authorised rather than relying on the fallback policy, which an application is
        // free to turn off.
        group.MapPost("/password", ChangePasswordAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaChangePassword")
            .WithSummary("Sets a first password or changes an existing one.")
            .WithDescription(
                "Send `currentPassword` when the account already has one and omit it when an "
                + "identity provider owns the account and it is gaining its first.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/password/forgot", ForgotPasswordAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaForgotPassword")
            .WithSummary("Requests a password reset link.")
            .WithDescription(
                "Always 204 - for an unknown address and for an account an identity provider owns "
                + "alike. The log says which.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/password/reset", ResetPasswordAsync)
            .AllowAnonymous()
            .WithName($"{endpointNamePrefix}ToamaisutaaResetPassword")
            .WithSummary("Redeems a reset token and sets a new password.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest);

        return group;
    }

    /// <summary>
    /// One body for every way a sign-in can fail. Wrong password, no such account and locked out are
    /// the same answer, because telling them apart tells a caller which user names are real.
    /// </summary>
    private static IResult SignInFailed() =>
        Results.Json(
            new ErrorResponse { Error = "invalid_grant", ErrorDescription = "The credentials are not valid." },
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
            return Results.Ok(new TwoFactorChallengeResponse
            {
                Challenge = challenge.Token,
                ExpiresIn = challenge.ExpiresIn,
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
    /// and no standard names them. <see cref="Toamaisutaa.Abstractions.TokenResponse"/> pins each
    /// name, so the decision survives a rename and an application's own JSON naming policy alike.
    /// </para>
    /// </remarks>
    internal static IResult SignInSucceeded(SignInResult result) =>
        Tokens(result.Tokens!, result.RecoveryCodesRunningLow, result.TrustedDevice, StatusCodes.Status200OK);

    internal static IResult Tokens(
        TokenPair tokens,
        bool recoveryCodesRunningLow,
        TrustedDeviceToken? trustedDevice,
        int statusCode) =>
        Results.Json(
            new TokenResponse
            {
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                ExpiresIn = tokens.ExpiresIn,
                TokenType = tokens.TokenType,

                // true or absent, never false: the shape 0.2.0 shipped, and clients read it as
                // truthy rather than comparing it.
                RecoveryCodesRunningLow = recoveryCodesRunningLow ? true : null,
                DeviceToken = trustedDevice?.Token,
                DeviceExpiresIn = trustedDevice?.ExpiresIn,
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
            return Tokens(result.Tokens!, false, null, StatusCodes.Status201Created);

        // Registration cannot hide whether an account exists without an email round trip, which
        // this package does not do. Documented, and why it is off by default.
        return result.Conflict
            ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
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

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
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

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }
}
