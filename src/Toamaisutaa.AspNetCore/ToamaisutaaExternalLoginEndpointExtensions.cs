using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaExternalLoginEndpointExtensions
{
    /// <summary>
    /// Maps <c>GET /auth/providers</c> and the sign-in, exchange and linking endpoints under
    /// <c>LocalLogin:EndpointPrefix</c> + <c>ExternalLogin:EndpointPrefix</c>. Maps nothing when no
    /// provider is configured.
    /// </summary>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name. Endpoint names are unique per application, so mapping into
    /// a second group needs a distinct prefix.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaExternalLoginEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaExternalLoginOptions>>().Value;
        var localLogin = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var root = endpoints.MapGroup(localLogin.EndpointPrefix).WithTags("External login");

        if (options.Providers.Count == 0)
            return root;

        root.WithMetadata(RequestBodyLimit.For(endpoints.ServiceProvider));
        root.AddEndpointFilter<StaleSecurityStampFilter>();

        root.MapGet("/providers", ListProviders)
            .AllowAnonymous()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalProviders")
            .WithSummary("Lists the identity providers a user can sign in with.")
            .WithDescription("Anonymous, so a sign-in page can draw a button per entry. `key` is what the other routes take.")
            .Produces<IReadOnlyList<ExternalProviderResponse>>();

        var group = root.MapGroup(options.EndpointPrefix);

        group.MapGet("/{provider}/start", StartAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalStart")
            .WithSummary("Sends the browser to a provider to sign in.")
            .WithDescription(
                "Navigate here, do not fetch it. Query: `returnUrl`, exactly one of `ExternalLogin:AllowedReturnUrls`; "
                + "`codeChallenge`, the base64url SHA-256 of a random verifier the client keeps; "
                + "`codeChallengeMethod=S256`; and optionally `state`, handed back untouched.\n\n"
                + "The browser comes back to `returnUrl` with `code`, to exchange at `/exchange` with the verifier, "
                + "or with `error`: `access_denied`, `account_exists`, `account_not_found` or `external_login_failed`.")
            .Produces(StatusCodes.Status302Found)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapGet("/{provider}/callback", CallbackAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalCallback")
            .WithSummary("Where the provider sends the browser back. Register this address with the provider.")
            .WithDescription(
                "Not for clients to call. Redirects to the `returnUrl` the sign-in began with; answers 400 only "
                + "when the answer belongs to no sign-in begun here, since then there is nowhere safe to send it.")
            .Produces(StatusCodes.Status302Found)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/exchange", ExchangeAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalExchange")
            .WithSummary("Exchanges the code a provider sign-in returned for tokens.")
            .WithDescription(
                "Send `{ \"code\": \"...\", \"codeVerifier\": \"...\" }`. Returns the same two shapes `/auth/login` "
                + "does: tokens with `fed` in `amr`, or a second-factor challenge for `/auth/2fa/verify`. A code is "
                + "spent by the first attempt, right verifier or not.")
            .Produces<TokenResponse>()
            .Produces<TwoFactorChallengeResponse>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/{provider}/link", LinkAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalLink")
            .WithSummary("Starts linking a provider to the caller's account.")
            .WithDescription(
                "Send `returnUrl` and the proof passkey registration takes: `code` where the account has a second "
                + "factor, `currentPassword` where it has a password, otherwise nothing beyond a sign-in within "
                + "`ExternalLogin:LinkProofWindow`. Navigate the browser to `authorization_url`; it comes back to "
                + "`returnUrl` with `linked`, or `error`: `linked_to_another_account`, `provider_already_linked` or "
                + "`external_login_failed`.")
            .Produces<ExternalLinkResponse>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapGet("/logins", ListLoginsAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalLogins")
            .WithSummary("Lists the providers linked to the caller's account.")
            .Produces<IReadOnlyList<ExternalLoginResponse>>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapDelete("/logins/{provider}", UnlinkAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaExternalUnlink")
            .WithSummary("Unlinks a provider. Takes the same proof linking does.")
            .WithDescription(
                "Refused with 400 when it is the account's only way to sign in. Unlinking ends every session on the "
                + "account, this one included, since the usual reason to remove a provider is that somebody else linked it.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        return root;
    }

    private static IResult ListProviders(IOptions<ToamaisutaaExternalLoginOptions> options) =>
        Results.Ok(options.Value.Providers
            .Select(entry => new ExternalProviderResponse
            {
                Key = entry.Key,
                DisplayName = entry.Value.DisplayName ?? entry.Key,
                IconUrl = entry.Value.IconUrl,
            })
            .ToList());

    private static async Task<IResult> StartAsync(
        string provider,
        string? returnUrl,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? state,
        HttpContext context,
        IOptions<ToamaisutaaExternalLoginOptions> options,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        if (!options.Value.Providers.ContainsKey(provider))
            return Results.NotFound();

        if (ReturnUrlProblem(returnUrl, state, options.Value) is { } problem)
            return Invalid(problem);

        // S256 only, and a verifier's worth of it: plain would hand the verifier to anyone reading the URL.
        if (codeChallengeMethod != "S256" || codeChallenge is not { Length: 43 } || !codeChallenge.All(IsBase64Url))
            return Invalid("Send codeChallenge, the base64url SHA-256 of a random verifier you keep, with codeChallengeMethod=S256.");

        var authorizationUrl = await externalLogins.BeginAsync(
            new ExternalLoginStart
            {
                ProviderKey = provider,
                RedirectUri = CallbackUri(context, provider),
                ReturnUrl = returnUrl!,
                ClientState = state,
                ClientCodeChallenge = codeChallenge,
            },
            cancellationToken);

        return Results.Redirect(authorizationUrl);
    }

    private static async Task<IResult> CallbackAsync(
        string provider,
        string? code,
        string? state,
        string? error,
        IOptions<ToamaisutaaExternalLoginOptions> options,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        var returnTo = options.Value.Providers.ContainsKey(provider)
            ? await externalLogins.CompleteAsync(provider, code, state, error, cancellationToken)
            : null;

        return returnTo is null
            ? Results.Json(
                new ErrorResponse
                {
                    Error = "invalid_request",
                    ErrorDescription = "This sign-in is unknown, already finished or expired. Start again.",
                },
                statusCode: StatusCodes.Status400BadRequest)
            : Results.Redirect(returnTo);
    }

    private static async Task<IResult> ExchangeAsync(
        ExternalLoginExchangeRequest request,
        HttpContext context,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.CodeVerifier))
            return ExchangeFailed();

        var result = await externalLogins.ExchangeAsync(
            new ExternalLoginExchange(
                request.Code,
                request.CodeVerifier,
                context.Request.Headers.UserAgent.ToString(),
                context.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);

        // Both bodies match /auth/login exactly, so clients handle one sign-in contract.
        if (result.Outcome == SignInOutcome.TwoFactorRequired && result.Challenge is { } challenge)
        {
            return Results.Ok(new TwoFactorChallengeResponse
            {
                Challenge = challenge.Token,
                ExpiresIn = challenge.ExpiresIn,
                SecondFactors = challenge.SecondFactors,
            });
        }

        return result.Succeeded ? ToamaisutaaPasswordEndpointExtensions.SignInSucceeded(result) : ExchangeFailed();
    }

    private static async Task<IResult> LinkAsync(
        string provider,
        LinkExternalLoginRequest request,
        HttpContext context,
        ICurrentUser currentUser,
        IOptions<ToamaisutaaExternalLoginOptions> options,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        if (!options.Value.Providers.ContainsKey(provider))
            return Results.NotFound();

        if (ReturnUrlProblem(request?.ReturnUrl, request?.State, options.Value) is { } problem)
            return Invalid(problem);

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        if (await externalLogins.ProveAsync(user.Id, Proof(context, request!.CurrentPassword, request.Code), cancellationToken) is { } refusal)
            return Invalid(refusal);

        var authorizationUrl = await externalLogins.BeginAsync(
            new ExternalLoginStart
            {
                ProviderKey = provider,
                RedirectUri = CallbackUri(context, provider),
                ReturnUrl = request.ReturnUrl,
                ClientState = request.State,
                LinkUser = user,
            },
            cancellationToken);

        return Results.Ok(new ExternalLinkResponse { AuthorizationUrl = authorizationUrl });
    }

    private static async Task<IResult> ListLoginsAsync(
        ICurrentUser currentUser,
        IOptions<ToamaisutaaExternalLoginOptions> options,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        var providers = options.Value.Providers;

        return Results.Ok((await externalLogins.ListAsync(user.Id, cancellationToken))
            .Select(login => new ExternalLoginResponse
            {
                Provider = login.ProviderKey,
                DisplayName = providers.TryGetValue(login.ProviderKey, out var configured) ? configured.DisplayName ?? login.ProviderKey : null,
                CreatedAt = login.CreatedAt,
                LastSignInAt = login.LastSignInAt,
            })
            .ToList());
    }

    private static async Task<IResult> UnlinkAsync(
        string provider,
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] UnlinkExternalLoginRequest? request,
        HttpContext context,
        ICurrentUser currentUser,
        ExternalLoginService externalLogins,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        if (await externalLogins.ProveAsync(user.Id, Proof(context, request?.CurrentPassword, request?.Code), cancellationToken) is { } refusal)
            return Invalid(refusal);

        return await externalLogins.UnlinkAsync(user.Id, provider, cancellationToken) switch
        {
            UnlinkOutcome.Unlinked => Results.NoContent(),
            UnlinkOutcome.LastWayIn => Invalid("This is the account's only way to sign in. Set a password or link another provider first."),
            _ => Results.NotFound(),
        };
    }

    /// <summary>When the caller signed in comes off its own token, never the body.</summary>
    private static ExternalLoginProof Proof(HttpContext context, string? currentPassword, string? code) => new()
    {
        CurrentPassword = currentPassword,
        Code = code,
        AuthenticatedAt = CallerAuthentication.AuthenticatedAt(context.User),
        SessionId = Guid.TryParse(context.User.FindFirst(ToamaisutaaDefaults.SessionIdClaim)?.Value, out var session) ? session : null,
    };

    /// <summary>Exact, whole-string: whatever matches receives a code that signs somebody in.</summary>
    private static string? ReturnUrlProblem(string? returnUrl, string? state, ToamaisutaaExternalLoginOptions options)
    {
        if (string.IsNullOrEmpty(returnUrl) || !options.AllowedReturnUrls.Contains(returnUrl, StringComparer.Ordinal))
            return "returnUrl must be exactly one of ExternalLogin:AllowedReturnUrls.";

        return state is { Length: > 512 } ? "state is longer than 512 characters." : null;
    }

    private static string CallbackUri(HttpContext context, string provider)
    {
        var settings = context.RequestServices.GetRequiredService<IOptions<ToamaisutaaExternalLoginOptions>>().Value;
        var localLogin = context.RequestServices.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var origin = settings.CallbackBaseUrl?.TrimEnd('/')
            ?? $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";

        return $"{origin}{localLogin.EndpointPrefix}{settings.EndpointPrefix}/{Uri.EscapeDataString(provider)}/callback";
    }

    private static bool IsBase64Url(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_';

    private static IResult Invalid(string message) =>
        Results.BadRequest(new ValidationErrorResponse { Errors = [message] });

    /// <summary>One body for every refusal, so a caller cannot tell a spent code from a disabled account.</summary>
    private static IResult ExchangeFailed() =>
        Results.Json(
            new ErrorResponse { Error = "invalid_grant", ErrorDescription = "That sign-in code is not valid." },
            statusCode: StatusCodes.Status401Unauthorized);
}
