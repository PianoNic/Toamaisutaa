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
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name, so the same endpoints can be mapped into more than one
    /// group. Endpoint names are unique per application, so a second group needs distinct ones.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaTwoFactorEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(options.EndpointPrefix + "/2fa").WithTags("Two-factor authentication");

        // Every endpoint here except /verify resolves the caller, and three of them move the stamp
        // themselves - so the token that called one is stale for the next request by design.
        group.AddEndpointFilter<StaleSecurityStampFilter>();

        group.MapGet("/", StatusAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorStatus")
            .WithSummary("Whether the caller has enrolled, and how many recovery codes remain.")
            .Produces<TwoFactorStatus>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/begin", BeginAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorBegin")
            .WithSummary("Generates a secret and stores it unconfirmed. Enables nothing.")
            .WithDescription(
                "The response carries the TOTP secret in plaintext, twice - as base32 and inside "
                + "the URI - because an authenticator cannot be enrolled without it. It is the one "
                + "response here that is itself a long-lived credential. Never log it, and keep it "
                + "out of any generic request or response logging you have.")
            .Produces<TwoFactorEnrolmentStarted>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/confirm", ConfirmAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorConfirm")
            .WithSummary("Proves the authenticator holds the secret, and turns the second factor on.")
            .WithDescription(
                "Returns the recovery codes, shown exactly once. Confirming also moves the user's "
                + "security stamp, which invalidates the access token used to call this - refresh "
                + "before the next request.")
            .Produces<TwoFactorEnrolmentCompleted>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/disable", DisableAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorDisable")
            .WithSummary("Turns the second factor off. Requires a current code as proof.")
            .WithDescription("An authenticated session is not enough: a stolen access token must not be able to do this.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/recovery-codes", RegenerateAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorRecoveryCodes")
            .WithSummary("Issues a fresh set of recovery codes and invalidates every previous one.")
            .WithDescription("Shown exactly once, and never logged. Same proof requirement as disabling.")
            .Produces<TwoFactorEnrolmentCompleted>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/step-up", BeginStepUpAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaStepUp")
            .WithSummary("Asks for a second factor from a session that is already signed in.")
            .WithDescription(
                "For satisfying a freshness policy without signing out. Takes no body: who you are "
                + "and which session you are on both come from your token. Present the challenge "
                + "with a code to `/auth/2fa/step-up/verify`.")
            .Produces<StepUpChallengeResponse>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/step-up/verify", CompleteStepUpAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaStepUpVerify")
            .WithSummary("Completes a step-up and returns a new access token for the same session.")
            .WithDescription(
                "**No refresh token comes back and none is needed** - your existing one keeps "
                + "working. Replace only the access token. A wrong code counts toward lockout, and "
                + "a recovery code works here and un-trusts every device, exactly as it does at "
                + "sign-in.")
            .Produces<StepUpResponse>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/verify", VerifyAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaTwoFactorVerify")
            .WithSummary("Finishes a sign-in that stopped for a second factor.")
            .WithDescription(
                "Anonymous, because the caller holds no token yet - the challenge is the credential. "
                + "`code` takes a TOTP code or a recovery code. Set `rememberDevice` to receive a "
                + "`device_token` alongside the tokens.")
            .Produces<TokenResponse>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

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
            return Results.BadRequest(new ValidationErrorResponse { Errors = [exception.Message] });
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
            return Results.BadRequest(new ValidationErrorResponse { Errors = [exception.Message] });
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

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
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
            return Results.BadRequest(new ValidationErrorResponse { Errors = [exception.Message] });
        }
    }

    private static async Task<IResult> VerifyAsync(
        VerifyTwoFactorRequest request,
        HttpContext context,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Code))
            return Unauthorized();

        var result = await signIn.VerifyTwoFactorAsync(
            new TwoFactorSignInRequest
            {
                ChallengeToken = request.Challenge,
                Code = request.Code,
                RememberDevice = request.RememberDevice,
                DeviceLabel = request.DeviceLabel,
                UserAgent = context.Request.Headers.UserAgent.ToString(),
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            },
            cancellationToken);

        // The same shape /auth/login returns, deliberately: these two endpoints both end a sign-in,
        // and a client that had to parse one casing here and another there would be carrying our
        // history rather than an API.
        return result.Succeeded
            ? ToamaisutaaPasswordEndpointExtensions.SignInSucceeded(result)
            : Unauthorized();
    }

    private static async Task<IResult> BeginStepUpAsync(
        HttpContext context,
        ICurrentUser currentUser,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (!TryReadSession(context, out var sessionId))
            return NotALocalSession();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        var result = await signIn.BeginStepUpAsync(
            new StepUpRequest { UserId = user.Id, SessionId = sessionId },
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(new StepUpChallengeResponse
            {
                Challenge = result.Challenge!.Token,
                ExpiresIn = result.Challenge.ExpiresIn,
            })
            : StepUpFailed(result.Outcome);
    }

    private static async Task<IResult> CompleteStepUpAsync(
        StepUpVerifyRequest request,
        HttpContext context,
        ICurrentUser currentUser,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Code))
            return Unauthorized();

        if (!TryReadSession(context, out var sessionId))
            return NotALocalSession();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        var result = await signIn.CompleteStepUpAsync(
            new StepUpVerificationRequest
            {
                UserId = user.Id,
                SessionId = sessionId,
                ChallengeToken = request.Challenge,
                Code = request.Code,
            },
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(new StepUpResponse
            {
                AccessToken = result.AccessToken!,
                ExpiresIn = result.ExpiresIn,
                RecoveryCodesRunningLow = result.RecoveryCodesRunningLow ? true : null,
            })
            : StepUpFailed(result.Outcome);
    }

    /// <summary>
    /// Reads <c>toa_sid</c>. Absent means the caller holds a token this package did not issue - an
    /// identity provider's, most likely - and there is no local session to elevate.
    /// </summary>
    private static bool TryReadSession(HttpContext context, out Guid sessionId) =>
        Guid.TryParse(context.User.FindFirst(ToamaisutaaDefaults.SessionIdClaim)?.Value, out sessionId);

    /// <summary>
    /// 400 rather than 401, deliberately. The token is fine and the caller is authenticated; what is
    /// missing is a local session, and answering 401 would send them to refresh a token that is not
    /// the problem.
    /// </summary>
    private static IResult NotALocalSession() =>
        Results.BadRequest(new ValidationErrorResponse
        {
            Errors = ["Step-up needs a session this application signed in. A token from an identity provider cannot be elevated here."],
        });

    private static IResult StepUpFailed(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.NotALocalSession => NotALocalSession(),

        SignInOutcome.TwoFactorNotEnrolled => Results.BadRequest(new ValidationErrorResponse
        {
            Errors = ["There is no confirmed second factor on this account to present."],
        }),

        // Everything else is one answer. Whether the session ended, the account is locked, or the
        // code was simply wrong is not something to confirm to whoever is holding the token.
        _ => Unauthorized(),
    };

    /// <summary>
    /// One body for a wrong code, an expired challenge, a spent one and an unknown one. They are the
    /// same answer to whoever is holding it, and telling them apart would say whether the challenge
    /// was ever real.
    /// </summary>
    private static IResult Unauthorized() =>
        Results.Json(
            new ErrorResponse { Error = "invalid_grant", ErrorDescription = "That code is not valid." },
            statusCode: StatusCodes.Status401Unauthorized);
}
