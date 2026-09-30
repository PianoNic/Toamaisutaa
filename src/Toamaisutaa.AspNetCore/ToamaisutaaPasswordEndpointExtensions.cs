using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;
using Toamaisutaa.Core;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaPasswordEndpointExtensions
{
    /// <summary>
    /// Maps the local sign-in endpoints under <c>LocalLogin:EndpointPrefix</c>.
    /// </summary>
    /// <remarks>
    /// The anonymous endpoints throttle themselves, so there is no rate-limiting middleware to add.
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
            // OpenAPI declares one schema per status code, so the second 200 shape is spelled out in prose.
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

        // Not mapped under HS256: an empty key set would be a 200 that makes a gateway silently refuse every token.
        var signingKeys = endpoints.ServiceProvider.GetRequiredService<LocalSigningKeyRing>();

        if (signingKeys.HasPublicKeys)
        {
            var jwks = signingKeys.PublicKeys();

            group.MapGet(ToamaisutaaDefaults.JwksEndpointPattern, () => Results.Ok(jwks))
                .AllowAnonymous()
                .WithName($"{endpointNamePrefix}ToamaisutaaJwks")
                .WithSummary("Publishes the public halves of the local signing keys.")
                .WithDescription(
                    "RFC 7517. Anonymous, because a gateway reads it before anyone has signed in. "
                    + "Mapped only when `LocalLogin:SigningKeys` is configured - a deployment "
                    + "signing HS256 has no public key to publish. Every configured key is here, "
                    + "not only the active one, so a token signed before a rotation still "
                    + "validates.")
                .Produces<JsonWebKeySetResponse>();
        }

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

        // Explicitly authorised because an application may turn the fallback policy off, and limited
        // because it checks a password.
        group.MapPost("/password", ChangePasswordAsync)
            .RequireAuthorization()
            .AddEndpointFilter<PasswordRateLimitFilter>()
            .WithName($"{endpointNamePrefix}ToamaisutaaChangePassword")
            .WithSummary("Sets a first password or changes an existing one.")
            .WithDescription(
                "Send `currentPassword` when the account already has one and omit it when an "
                + "identity provider owns the account and it is gaining its first. A wrong "
                + "`currentPassword` counts toward the account lockout.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests);

        group.MapPost("/password/forgot", ForgotPassword)
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

        if (endpoints.ServiceProvider.GetService<IEmailVerificationNotifier>() is not null)
        {
            group.MapPost("/email", ChangeEmailAsync)
                .RequireAuthorization()
                .AddEndpointFilter<PasswordRateLimitFilter>()
                .WithName($"{endpointNamePrefix}ToamaisutaaChangeEmail")
                .WithSummary("Sends a verification link to an address, and changes nothing yet.")
                .WithDescription(
                    "`currentPassword` is required, including when `newEmail` is the address the account already has - "
                    + "which is how a verification link is asked for again. The account moves only when the link is "
                    + "redeemed at /auth/email/verify. A wrong `currentPassword` counts toward the account lockout.")
                .Produces(StatusCodes.Status204NoContent)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces<ValidationErrorResponse>(StatusCodes.Status409Conflict)
                .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)

                // With a body, unlike the limiter's 429 elsewhere: the per-account cooldown says why.
                .Produces<ValidationErrorResponse>(StatusCodes.Status429TooManyRequests);

            group.MapPost("/email/verify", VerifyEmailAsync)
                .AllowAnonymous()
                .WithName($"{endpointNamePrefix}ToamaisutaaVerifyEmail")
                .WithSummary("Redeems a verification token and writes the address it names.")
                .WithDescription(
                    "Anonymous, because the link is opened from a mailbox and often on another device. The token is "
                    + "what proves anything here.")
                .Produces(StatusCodes.Status204NoContent)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces<ValidationErrorResponse>(StatusCodes.Status409Conflict);
        }

        if (endpoints.ServiceProvider.GetService<IMagicLinkNotifier>() is not null)
        {
            group.MapPost("/magic-link", RequestMagicLink)
                .AllowAnonymous()
                .AddEndpointFilter<PasswordRateLimitFilter>()
                .WithName($"{endpointNamePrefix}ToamaisutaaMagicLink")
                .WithSummary("Requests a single-use sign-in link.")
                .WithDescription(
                    "Always 204 - for an unknown address, for an account an identity provider owns, and for an "
                    + "address nobody has verified alike. The log says which. A link is only ever sent to a verified "
                    + "address, because redeeming one is a sign-in rather than a step towards one.")
                .Produces(StatusCodes.Status204NoContent)
                .Produces(StatusCodes.Status429TooManyRequests);

            group.MapPost("/magic-link/verify", VerifyMagicLinkAsync)
                .AllowAnonymous()
                .AddEndpointFilter<PasswordRateLimitFilter>()
                .WithName($"{endpointNamePrefix}ToamaisutaaVerifyMagicLink")
                .WithSummary("Redeems a sign-in link for a token pair, or asks for a second factor.")
                .WithDescription(
                    "**Two success shapes, both 200.** Usually a token pair, with `amr` carrying `email` rather than "
                    + "`pwd` - no password was typed. For a user with a confirmed second factor it is instead a "
                    + "challenge and no tokens:\n\n"
                    + "```json\n{ \"two_factor_required\": true, \"challenge\": \"No1CXq9-...\", \"expires_in\": 300 }\n```\n\n"
                    + "Present it with a code to `/auth/2fa/verify`, the same endpoint a password sign-in uses. A "
                    + "trusted device does not skip that challenge here.")
                .Produces<TwoFactorChallengeResponse>()
                .Produces<TokenResponse>()
                .Produces<ErrorResponse>(StatusCodes.Status401Unauthorized)
                .Produces(StatusCodes.Status429TooManyRequests);
        }

        // The admin endpoints act on any account by id, so they need the admin policy, not the default,
        // and are not mapped at all when no admin role is configured.
        var adminPolicy = AdminPolicyName(endpoints.ServiceProvider);

        var hasAdminPasswordNotifier = endpoints.ServiceProvider.GetService<IAdminPasswordIssuedNotifier>() is not null;
        var hasInvitationNotifier = endpoints.ServiceProvider.GetService<IInvitationNotifier>() is not null;

        if (adminPolicy is null && (hasAdminPasswordNotifier || hasInvitationNotifier))
        {
            endpoints.ServiceProvider.GetService<ILoggerFactory>()
                ?.CreateLogger(typeof(ToamaisutaaPasswordEndpointExtensions).FullName!)
                .LogWarning(
                    "A provisioning notifier is registered but Oidc:AdminRole is not set, so /auth/users, "
                    + "/auth/users/{{userId}}/password and /auth/invitations were not mapped. They act on any "
                    + "account by id, so they require an admin policy, and that policy is registered only when "
                    + "Oidc:AdminRole names a role.");
        }

        if (hasAdminPasswordNotifier && adminPolicy is not null)
        {
            group.MapPost("/users", CreateUserAsync)
                .RequireAuthorization(adminPolicy)
                .WithName($"{endpointNamePrefix}ToamaisutaaCreateUser")
                .WithSummary("Creates a local account on someone else's behalf.")
                .WithDescription(
                    "Never signs the caller in as the new account, and never returns a password - the raw value, "
                    + "typed or generated, goes to IAdminPasswordIssuedNotifier instead. Requires the admin role "
                    + "`Oidc:AdminRole` names.")
                .Produces<AdminAccountResponse>(StatusCodes.Status201Created)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces(StatusCodes.Status403Forbidden)
                .Produces<ValidationErrorResponse>(StatusCodes.Status409Conflict);

            group.MapPost("/users/{userId:guid}/password", SetUserPasswordAsync)
                .RequireAuthorization(adminPolicy)
                .WithName($"{endpointNamePrefix}ToamaisutaaSetUserPassword")
                .WithSummary("Overwrites a user's password, generating one if none is given.")
                .WithDescription(
                    "Unconditional - no current password is checked, because the caller is acting on someone "
                    + "else's account - and revokes every local session the account holds. Requires the admin "
                    + "role `Oidc:AdminRole` names.\n\n"
                    + "**502** means the password was set and the sessions revoked but "
                    + "IAdminPasswordIssuedNotifier could not deliver it, so nobody has the new value. Set one "
                    + "again once delivery works.")
                .Produces(StatusCodes.Status204NoContent)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces(StatusCodes.Status403Forbidden)
                .Produces<ErrorResponse>(StatusCodes.Status502BadGateway);
        }

        if (hasInvitationNotifier)
        {
            if (adminPolicy is not null)
            {
                group.MapPost("/invitations", CreateInvitationAsync)
                    .RequireAuthorization(adminPolicy)
                    .WithName($"{endpointNamePrefix}ToamaisutaaCreateInvitation")
                    .WithSummary("Reserves an account with nothing but an email.")
                    .WithDescription(
                        "No user name and no credential yet - the invited person chooses both at "
                        + "/auth/invitations/complete. Never returns the invitation token, which goes to "
                        + "IInvitationNotifier instead. Requires the admin role `Oidc:AdminRole` names.\n\n"
                        + "**502** means IInvitationNotifier could not deliver the token, and nothing was "
                        + "reserved - the row and the token are rolled back, so a retry is safe.")
                    .Produces<InvitationResponse>(StatusCodes.Status201Created)
                    .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                    .Produces(StatusCodes.Status403Forbidden)
                    .Produces<ErrorResponse>(StatusCodes.Status502BadGateway);

                group.MapPost("/invitations/revoke", RevokeInvitationAsync)
                    .RequireAuthorization(adminPolicy)
                    .WithName($"{endpointNamePrefix}ToamaisutaaRevokeInvitation")
                    .WithSummary("Withdraws an open invitation and removes the account it reserved.")
                    .WithDescription(
                        "404 when the address has no open invitation - including one already completed into "
                        + "an account, which this never touches. Requires the admin role `Oidc:AdminRole` names.")
                    .Produces(StatusCodes.Status204NoContent)
                    .Produces(StatusCodes.Status400BadRequest)
                    .Produces(StatusCodes.Status403Forbidden)
                    .Produces(StatusCodes.Status404NotFound);
            }

            // Mapped even without an admin role, because invitations may be created by a worker rather than over HTTP.
            group.MapPost("/invitations/complete", CompleteInvitationAsync)
                .AllowAnonymous()
                .WithName($"{endpointNamePrefix}ToamaisutaaCompleteInvitation")
                .WithSummary("Sets the user name and password on the one reserved account a token names.")
                .WithDescription(
                    "Signs in on success, the same shape /auth/register answers with. Not open "
                    + "registration - completing an invitation only ever touches the single row the "
                    + "token was issued for.")
                .Produces<TokenResponse>(StatusCodes.Status201Created)
                .Produces<ValidationErrorResponse>(StatusCodes.Status400BadRequest)
                .Produces<ValidationErrorResponse>(StatusCodes.Status409Conflict);
        }

        return group;
    }

    /// <summary>
    /// Uses the same condition that registers the policy, so a route can never require one that was never added.
    /// </summary>
    private static string? AdminPolicyName(IServiceProvider services)
    {
        var authorization = services.GetService<IOptions<ToamaisutaaAuthorizationOptions>>()?.Value;

        return string.IsNullOrWhiteSpace(authorization?.AdminRole) ? null : authorization.AdminPolicyName;
    }

    /// <summary>
    /// One body for every failure, because telling them apart tells a caller which user names are real.
    /// </summary>
    private static IResult SignInFailed() =>
        Results.Json(
            new ErrorResponse { Error = "invalid_grant", ErrorDescription = "The credentials are not valid." },
            statusCode: StatusCodes.Status401Unauthorized);

    private static async Task<IResult> LoginAsync(
        LoginRequest request,
        HttpContext context,
        IPasswordSignInService signIn,
        IOptions<ToamaisutaaLocalLoginOptions> options,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Identifier) || string.IsNullOrEmpty(request.Password))
            return SignInFailed();

        var started = Stopwatch.GetTimestamp();

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

        if (result.Outcome == SignInOutcome.TwoFactorRequired && result.Challenge is { } challenge)
        {
            return Results.Ok(new TwoFactorChallengeResponse
            {
                Challenge = challenge.Token,
                ExpiresIn = challenge.ExpiresIn,
            });
        }

        if (result.Succeeded)
            return SignInSucceeded(result);

        // Every refusal takes at least the floor, so response time cannot reveal which accounts exist.
        var remaining = options.Value.SignInRefusalFloor - Stopwatch.GetElapsedTime(started);
        if (remaining > TimeSpan.Zero)
            await Task.Delay(remaining, cancellationToken);

        return SignInFailed();
    }

    /// <summary>
    /// The one place a successful sign-in is shaped, so every endpoint returns the rotated device token;
    /// dropping it leaves the caller a dead token whose reuse revokes the family.
    /// </summary>
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

                // True or absent, never false: clients read it as truthy.
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

        // 409 reveals the account exists, which is documented and why self-registration is off by default.
        return result.Conflict
            ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }

    private static async Task<IResult> ChangePasswordAsync(
        ChangePasswordRequest request,
        HttpContext context,
        ICurrentUser currentUser,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.NewPassword))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);

        var result = await accounts.SetPasswordAsync(
            user.Id,
            request.CurrentPassword,
            request.NewPassword,
            CallerAuthentication.AuthenticatedAt(context.User),
            cancellationToken);

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }

    private static IResult ForgotPassword(
        ForgotPasswordRequest request,
        MailRequestQueue queue,
        MailRequestCooldown cooldown)
    {
        // Queued rather than awaited, so response time cannot reveal whether the address has an account.
        if (request is not null && !string.IsNullOrEmpty(request.Email) && cooldown.TryEnter("reset", request.Email))
        {
            var email = request.Email;

            // Dropped, so nothing was sent, and the cooldown must not also turn away the retry.
            if (!queue.Enqueue((services, cancellationToken) =>
                    services.GetRequiredService<IPasswordAccountService>().RequestPasswordResetAsync(email, cancellationToken)))
            {
                cooldown.Release("reset", email);
            }
        }

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

    private static string Spoken(TimeSpan period) => period.TotalSeconds < 60
        ? $"{Math.Ceiling(period.TotalSeconds)} seconds"
        : Math.Ceiling(period.TotalMinutes) is 1 ? "a minute" : $"{Math.Ceiling(period.TotalMinutes)} minutes";

    private static async Task<IResult> ChangeEmailAsync(
        ChangeEmailRequest request,
        ICurrentUser currentUser,
        IPasswordAccountService accounts,
        MailRequestCooldown cooldown,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.NewEmail) || string.IsNullOrEmpty(request.CurrentPassword))
            return Results.BadRequest();

        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        var account = user.Id.ToString();

        // Per account, because the recipient is whatever the caller types; answered openly since it is their own account.
        if (!cooldown.TryEnter("email-change", account))
        {
            return Results.Json(
                new ValidationErrorResponse { Errors = [$"A verification link was sent a moment ago. Wait {Spoken(cooldown.Period)} before asking for another."] },
                statusCode: StatusCodes.Status429TooManyRequests);
        }

        AccountResult result;

        try
        {
            result = await accounts.RequestEmailChangeAsync(user.Id, request.NewEmail, request.CurrentPassword, cancellationToken);
        }
        catch
        {
            // A mail server that timed out sent nothing, and the retry must not be told it did.
            cooldown.Release("email-change", account);
            throw;
        }

        if (result.Succeeded)
            return Results.NoContent();

        cooldown.Release("email-change", account);

        return result.Conflict
            ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }

    private static async Task<IResult> VerifyEmailAsync(
        VerifyEmailRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Token))
            return Results.BadRequest();

        var result = await accounts.VerifyEmailAsync(request.Token, cancellationToken);

        if (result.Succeeded)
            return Results.NoContent();

        return result.Conflict
            ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }

    private static IResult RequestMagicLink(
        MagicLinkRequest request,
        MailRequestQueue queue,
        MailRequestCooldown cooldown)
    {
        // Queued so response time cannot reveal whether the address has an account.
        if (request is not null && !string.IsNullOrEmpty(request.Email) && cooldown.TryEnter("magic-link", request.Email))
        {
            var email = request.Email;

            if (!queue.Enqueue((services, cancellationToken) =>
                    services.GetRequiredService<IPasswordAccountService>().RequestMagicLinkAsync(email, cancellationToken)))
            {
                cooldown.Release("magic-link", email);
            }
        }

        return Results.NoContent();
    }

    private static async Task<IResult> VerifyMagicLinkAsync(
        VerifyMagicLinkRequest request,
        HttpContext context,
        IPasswordSignInService signIn,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Token))
            return SignInFailed();

        var result = await signIn.VerifyMagicLinkAsync(
            new MagicLinkSignInRequest
            {
                Token = request.Token,
                UserAgent = context.Request.Headers.UserAgent.ToString(),
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            },
            cancellationToken);

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

    private static async Task<IResult> CreateUserAsync(
        CreateUserRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.UserName))
            return Results.BadRequest();

        var result = await accounts.AdminCreateAccountAsync(request.UserName, request.Email, request.Password, cancellationToken);

        if (!result.Succeeded)
        {
            return result.Conflict
                ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
                : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
        }

        return Results.Json(
            new AdminAccountResponse { UserId = result.UserId!.Value, UserName = request.UserName, Email = request.Email },
            statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> SetUserPasswordAsync(
        Guid userId,
        SetUserPasswordRequest? request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        var result = await accounts.AdminSetPasswordAsync(userId, request?.Password, cancellationToken);

        // Not a 204: the password was set but reached nobody, so success would leave an account nobody can open.
        if (result.NotificationFailed)
        {
            return Results.Json(
                new ErrorResponse
                {
                    Error = "notification_failed",
                    ErrorDescription =
                        "The password was set and every session revoked, but IAdminPasswordIssuedNotifier could "
                        + "not deliver it. Nobody has the new password. Set one again once delivery works.",
                },
                statusCode: StatusCodes.Status502BadGateway);
        }

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
    }

    private static async Task<IResult> RevokeInvitationAsync(
        RevokeInvitationRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Email))
            return Results.BadRequest();

        return await accounts.RevokeInvitationAsync(request.Email, cancellationToken)
            ? Results.NoContent()
            : Results.NotFound();
    }

    private static async Task<IResult> CreateInvitationAsync(
        CreateInvitationRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Email))
            return Results.BadRequest();

        var result = await accounts.CreateInvitationAsync(request.Email, cancellationToken);

        // Not a 400: nothing the caller can correct, and the same request works once the notifier does.
        if (result.NotificationFailed)
        {
            return Results.Json(
                new ErrorResponse
                {
                    Error = "notification_failed",
                    ErrorDescription =
                        "IInvitationNotifier could not deliver the invitation, so no account was reserved. "
                        + "Try again once delivery works.",
                },
                statusCode: StatusCodes.Status502BadGateway);
        }

        if (!result.Succeeded)
            return Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });

        return Results.Json(
            new InvitationResponse { UserId = result.UserId!.Value, Email = request.Email },
            statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> CompleteInvitationAsync(
        CompleteInvitationRequest request,
        IPasswordAccountService accounts,
        CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrEmpty(request.Token) || string.IsNullOrEmpty(request.UserName) || string.IsNullOrEmpty(request.Password))
            return Results.BadRequest();

        var result = await accounts.CompleteInvitationAsync(request.Token, request.UserName, request.Password, cancellationToken);

        if (!result.Succeeded)
        {
            return result.Conflict
                ? Results.Json(new ValidationErrorResponse { Errors = result.Errors }, statusCode: StatusCodes.Status409Conflict)
                : Results.BadRequest(new ValidationErrorResponse { Errors = result.Errors });
        }

        return Tokens(result.Tokens!, false, null, StatusCodes.Status201Created);
    }
}
