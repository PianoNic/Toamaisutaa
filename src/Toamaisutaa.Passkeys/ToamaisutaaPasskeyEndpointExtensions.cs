using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Passkeys;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaPasskeyEndpointExtensions
{
    /// <summary>
    /// Maps the two ceremonies, the credential list and the delete under
    /// <c>LocalLogin:EndpointPrefix</c> + <c>Passkeys:EndpointPrefix</c>.
    /// </summary>
    /// <remarks>
    /// The assertion pair is anonymous, because a passkey is the first credential rather than a
    /// second one - there is no token yet. Both halves are throttled by the same limiter as
    /// <c>/auth/login</c>, and so is <c>/register/begin</c>, which writes a row on every call.
    /// </remarks>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="endpointNamePrefix">
    /// Prepended to every endpoint name, so the same endpoints can be mapped into more than one
    /// group. Endpoint names are unique per application, so a second group needs distinct ones.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaPasskeyEndpoints(
        this IEndpointRouteBuilder endpoints,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaPasskeyOptions>>().Value;
        var localLogin = endpoints.ServiceProvider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;

        var group = endpoints.MapGroup(localLogin.EndpointPrefix + options.EndpointPrefix).WithTags("Passkeys");

        // Four of the six resolve the caller, so they can meet a token whose stamp has moved.
        group.AddEndpointFilter<StaleSecurityStampFilter>();

        group.MapGet("/", ListAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaPasskeys")
            .WithSummary("Lists the passkeys this user has registered.")
            .WithDescription(
                "`isBackedUp` says whether the user's own provider is syncing the credential across "
                + "their devices, which is the difference between losing a laptop and losing the "
                + "account. `lastUsedAt` is null for one that has never signed anything.")
            .Produces<IReadOnlyList<PasskeySummary>>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaDeletePasskey")
            .WithSummary("Deletes one passkey by its id.")
            .WithDescription(
                "404 covers both a passkey that does not exist and one belonging to someone else, so "
                + "this cannot be used to discover another account's credential ids. Deleting the "
                + "last one on an account with no password leaves nothing to sign in with.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound);

        group.MapPost("/register/begin", BeginRegistrationAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaPasskeyRegisterBegin")
            .WithSummary("Starts a registration. Takes proof of a credential the account already has.")
            .WithDescription(
                "Send `currentPassword`, or call this from a session that presented a second factor "
                + "within `Passkeys:RegistrationProofWindow` - a passkey sign-in or a step-up. A "
                + "bearer token alone is not enough: a passkey signs in on its own, so adding one "
                + "adds a way into the account.\n\n"
                + "`options` goes to `navigator.credentials.create()` once its base64url fields are "
                + "decoded. `challenge` is this package's own opaque handle on the ceremony, not the "
                + "WebAuthn challenge - hand it back to `/register/complete`.")
            .Produces<PasskeyChallengeResponse>()
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/register/complete", CompleteRegistrationAsync)
            .RequireAuthorization()
            .WithName($"{endpointNamePrefix}ToamaisutaaPasskeyRegisterComplete")
            .WithSummary("Verifies what the authenticator produced and stores the credential.")
            .WithDescription(
                "The proof was given to `/register/begin`, and the challenge it returned is what "
                + "stands for it here. Registering changes no credential the account already has, so "
                + "the calling token stays valid.")
            .Produces<PasskeySummary>(StatusCodes.Status201Created)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized);

        group.MapPost("/assertion/begin", BeginAssertionAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaPasskeyAssertionBegin")
            .WithSummary("Starts a passwordless sign-in.")
            .WithDescription(
                "Anonymous, and takes no identifier: the browser finds a discoverable credential "
                + "itself, so there is no user name box and nothing here that can answer whether an "
                + "account exists. `options` goes to `navigator.credentials.get()`.")
            .Produces<PasskeyChallengeResponse>()
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/assertion/complete", CompleteAssertionAsync)
            .AllowAnonymous()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaPasskeyAssertionComplete")
            .WithSummary("Verifies an assertion and signs the user in.")
            .WithDescription(
                "Returns the same body `/auth/login` does. The token carries `hwk` and `user` in "
                + "`amr`, plus `mfa` when the authenticator verified the user - which is what lets a "
                + "passkey satisfy the two-factor policy without a TOTP code.\n\n"
                + "An assertion the authenticator did not verify the user for proved possession "
                + "alone, so an account with a confirmed enrolment gets the same challenge shape "
                + "`/auth/login` answers with:\n\n"
                + "```json\n{ \"two_factor_required\": true, \"challenge\": \"No1CXq9-...\", \"expires_in\": 300 }\n```\n\n"
                + "Present it with a code to `/auth/2fa/verify`.")
            .Produces<TokenResponse>()
            .Produces<TwoFactorChallengeResponse>()
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        return group;
    }

    private static async Task<IResult> ListAsync(
        ICurrentUser currentUser,
        IPasskeyService passkeys,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        return Results.Ok(await passkeys.ListAsync(user.Id, cancellationToken));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        ICurrentUser currentUser,
        IPasskeyService passkeys,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        return await passkeys.DeleteAsync(user.Id, id, cancellationToken)
            ? Results.NoContent()
            : Results.NotFound();
    }

    private static async Task<IResult> BeginRegistrationAsync(
        PasskeyRegistrationProof? proof,
        HttpContext context,
        ICurrentUser currentUser,
        IPasskeyService passkeys,
        CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        // The second factor comes off the caller's own token rather than the body. It is the one
        // half of the proof a caller could otherwise assert about themselves.
        var presented = (proof ?? new PasskeyRegistrationProof()) with { SecondFactorAt = SecondFactorAt(context.User) };

        try
        {
            return Ceremony(await passkeys.BeginRegistrationAsync(user.Id, presented, cancellationToken));
        }
        catch (PasskeyRegistrationException exception)
        {
            return Results.BadRequest(new ValidationErrorResponse { Errors = [exception.Message] });
        }
    }

    /// <summary>
    /// When this session last presented a live second factor, from <c>toa_2fa_at</c>.
    /// </summary>
    /// <remarks>
    /// The same claim <c>RequireFreshSecondFactor</c> reads, so "fresh" means one thing across the
    /// package: a device-trusted sign-in reports the original challenge rather than now, and a
    /// session that cached its way in does not count as having proved anything just now.
    /// </remarks>
    private static DateTimeOffset? SecondFactorAt(ClaimsPrincipal principal) =>
        long.TryParse(
            principal.FindFirst(ToamaisutaaDefaults.SecondFactorAtClaim)?.Value,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var unixSeconds)
            ? DateTimeOffset.FromUnixTimeSeconds(unixSeconds)
            : null;

    private static async Task<IResult> CompleteRegistrationAsync(
        PasskeyRegistrationRequest request,
        ICurrentUser currentUser,
        IPasskeyService passkeys,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Id))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        try
        {
            var registered = await passkeys.CompleteRegistrationAsync(user.Id, request, cancellationToken);

            // No Location, matching every other 201 in the package. There is no route that serves
            // one credential - the id in this body is for the delete and for the list - and a header
            // naming a path nothing maps is worse than no header at all.
            return Results.Json(registered, statusCode: StatusCodes.Status201Created);
        }
        catch (PasskeyRegistrationException exception)
        {
            return Results.BadRequest(new ValidationErrorResponse { Errors = [exception.Message] });
        }
    }

    private static async Task<IResult> BeginAssertionAsync(IPasskeyService passkeys, CancellationToken cancellationToken) =>
        Ceremony(await passkeys.BeginAssertionAsync(cancellationToken));

    private static async Task<IResult> CompleteAssertionAsync(
        PasskeyAssertionRequest request,
        HttpContext context,
        IPasskeyService passkeys,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Challenge) || string.IsNullOrWhiteSpace(request.Id))
            return Unauthorized();

        var result = await passkeys.CompleteAssertionAsync(
            request with
            {
                UserAgent = context.Request.Headers.UserAgent.ToString(),
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            },
            cancellationToken);

        // Possession without user verification, on an account that has enrolled. The same second
        // shape /auth/login answers with, for the same reason the body below is the same one: a
        // client that had to learn a second way of being asked for a code would have two of them.
        if (result.Outcome == SignInOutcome.TwoFactorRequired && result.Challenge is { } challenge)
        {
            return Results.Ok(new TwoFactorChallengeResponse
            {
                Challenge = challenge.Token,
                ExpiresIn = challenge.ExpiresIn,
            });
        }

        // The same body /auth/login returns, deliberately: both end a sign-in, and a client that had
        // to parse one casing here and another there would be carrying our history rather than an API.
        return result.Succeeded
            ? ToamaisutaaPasswordEndpointExtensions.Tokens(
                result.Tokens!,
                recoveryCodesRunningLow: false,
                trustedDevice: null,
                StatusCodes.Status200OK)
            : Unauthorized();
    }

    private static IResult Ceremony(PasskeyCeremonyStarted started) =>
        Results.Ok(new PasskeyChallengeResponse
        {
            Challenge = started.Challenge,
            ExpiresIn = started.ExpiresIn,
            Options = started.Options,
        });

    /// <summary>
    /// One body for a wrong signature, an expired challenge, a spent one and a credential nobody has
    /// registered. They are the same answer to whoever presented it, and telling them apart would
    /// say whether the credential was ever real.
    /// </summary>
    private static IResult Unauthorized() =>
        Results.Json(
            new ErrorResponse { Error = "invalid_grant", ErrorDescription = "That passkey is not valid." },
            statusCode: StatusCodes.Status401Unauthorized);
}
