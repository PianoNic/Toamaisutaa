using System.Diagnostics.Metrics;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// The package describes its own endpoints - every response type, every status code - but a security
// scheme is a document-level declaration, so somebody has to add it or an API explorer offers no
// Authorize box, which is how most people first meet an API. This is the Bearer scheme for tokens
// this application issues, an OAuth2 scheme whose URLs come from the identity provider's discovery
// document, and no padlock on the anonymous endpoints.
builder.Services.AddToamaisutaaOpenApi(builder.Configuration);

// Validate access tokens. Both the identity provider's and the ones this application issues itself:
// one handler, one scheme, and nothing downstream can tell which kind it is holding.
builder.Services.AddToamaisutaaBearer(builder.Configuration);

// Probes the issuer's discovery document, so a wrong Oidc:Authority is a red readiness check rather
// than a 401 on every request. Start the sample without the mock issuer running and /health says so
// in one line.
builder.Services.AddToamaisutaaHealthChecks();

// Authenticated by default, plus the "Toamaisutaa.Admin" policy because Oidc:AdminRole is set.
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(
    builder.Configuration.GetConnectionString("Toamaisutaa") ?? "Data Source=toamaisutaa-sample.db",
    // Migrations are provider-specific, so the assembly holding them is named here rather than
    // guessed. Swap in the Postgres one and nothing else changes.
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
builder.Services.AddToamaisutaaCurrentUser();

// Argon2id instead of the in-box PBKDF2, from an opt-in package - memory-hard, and the dependency
// that needs is installed here rather than by the library. Drop this line and every account still
// signs in: the rows say what made them, so the two hashers read each other's and each password is
// rewritten under whichever one is registered the next time its owner logs in.
builder.Services.AddToamaisutaaArgon2PasswordHashing(builder.Configuration);

// Local username and password sign-in. OIDC is the recommended path; this is the fallback for a
// deployment that cannot run an identity provider.
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);

// Refuses passwords the Pwned Passwords corpus has seen, on top of the length floor rather than in
// place of it. It talks to a third party, so try "password" against /auth/register to watch it work
// and pull the network cable to watch it let one through with a warning instead.
builder.Services.AddToamaisutaaHibpPasswordValidation(builder.Configuration);

// TOTP. Enrolment is per user and entirely opt-in here, because TwoFactor:Enforcement is Optional -
// but anyone who does enrol is challenged on every local sign-in from then on.
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);

// Remember this device: skip the second factor on a device that already completed a live challenge.
// A cached second factor, and nothing more - it never stands in for the password, and every
// credential change takes it with them.
builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);

builder.Services.AddToamaisutaaTokenCleanup();

// Nothing switches the metrics on - the meter is always there. This subscribes to it and writes
// every measurement to the log, which is what an exporter does with somewhere better to put it.
// Sign in, mistype a password, redeem a recovery code, and watch the counters move. The real wiring
// is one AddMeter call: see docs/metrics.md.
builder.Services.AddHostedService<MetricsToTheLog>();

// Freshness, on top of the Toamaisutaa.TwoFactor policy the package registers. A 403 from this is
// what /auth/2fa/step-up is for.
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("FreshSecondFactor", policy => policy
        .RequireAuthenticatedUser()
        .RequireFreshSecondFactor(TimeSpan.FromMinutes(2)));

// Required, and deliberately not shipped: sending mail is not an authentication library's job. This
// one writes the link to the log, which is all a sample needs.
builder.Services.AddSingleton<IPasswordResetNotifier, LoggingPasswordResetNotifier>();

// Every security-relevant outcome, handed to whatever you register: sign-ins, lockouts, password
// changes, two-factor and device events, refresh-token reuse. This one writes a line; a real one
// writes a row. Nothing published ever carries a secret, which is what makes it safe to keep for as
// long as an audit table is kept.
builder.Services.AddToamaisutaaAuthenticationEventSink<LoggingAuditSink>();

// Optional, unlike the reset notifier, and registering it is what puts /auth/email and
// /auth/email/verify on the wire at all. Comment this line out and both endpoints are gone.
builder.Services.AddSingleton<IEmailVerificationNotifier, LoggingEmailVerificationNotifier>();

// The same shape again, and the one to be most careful with: this token is not a step towards a
// session, it is the session. Registering the notifier is what puts /auth/magic-link and
// /auth/magic-link/verify on the wire, and startup refuses it without the verification notifier
// above - a link only ever goes to an address somebody has proven.
builder.Services.AddSingleton<IMagicLinkNotifier, LoggingMagicLinkNotifier>();

// Toamaisutaa's own endpoints already answer 401 for a stale security stamp. This covers YOUR
// endpoints: anything calling ICurrentUser.GetOrProvisionAsync can meet a token that was issued
// before a credential changed, and without this it surfaces as a 500 for something the client only
// needed to refresh. /api/me below is exactly that shape.
builder.Services.AddExceptionHandler<StaleSecurityStampHandler>();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();

await using (var scope = app.Services.CreateAsyncScope())
{
    await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.MigrateAsync();
}

app.UseAuthentication();
app.UseAuthorization();

// What the SPA reads at startup to configure its OIDC client. Anonymous, since it is needed before
// anyone has signed in.
app.MapToamaisutaaConfiguration();

// POST /auth/login, /auth/refresh, /auth/logout, /auth/register, /auth/password,
// /auth/password/forgot, /auth/password/reset, /auth/email, /auth/email/verify,
// /auth/magic-link, /auth/magic-link/verify.
app.MapToamaisutaaPasswordEndpoints();

// GET /auth/2fa, POST /auth/2fa/begin, /auth/2fa/confirm, /auth/2fa/disable,
// /auth/2fa/recovery-codes, /auth/2fa/verify.
app.MapToamaisutaaTwoFactorEndpoints();

// GET /auth/devices, DELETE /auth/devices/{id}, DELETE /auth/devices.
app.MapToamaisutaaTrustedDeviceEndpoints();

// GET /auth/sessions, DELETE /auth/sessions/{id}, DELETE /auth/sessions. One entry per sign-in
// rather than per access token, because a session here is the refresh family that toa_sid names.
// The last of the three signs out everywhere ELSE - the page you clicked it on stays signed in.
app.MapToamaisutaaSessionEndpoints();

// Anonymous, and it has to be: the fallback policy would otherwise answer 401, which an orchestrator
// reads as a failing probe no matter how healthy the issuer is.
app.MapHealthChecks("/health").AllowAnonymous();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();

    // http://localhost:5203/scalar - the document above, rendered. The Authorize button comes from
    // the security schemes AddToamaisutaaOpenApi declared.
    app.MapScalarApiReference(options => options.WithTitle("Toamaisutaa sample")).AllowAnonymous();
}

app.MapGet("/api/public", () => "The gate stands open here. No token needed.")
    .AllowAnonymous()
    .WithName("Public");

// The fallback policy covers this: no token, no answer. It does not care whether the token came
// from the identity provider or from /auth/login.
app.MapGet("/api/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
{
    var user = await currentUser.GetOrProvisionAsync(cancellationToken);

    return Results.Ok(new
    {
        Local = new { user.Id, user.UserName, user.DisplayName, user.Email, user.CreatedAt, user.UpdatedAt },
        FromToken = new
        {
            currentUser.Subject,
            Actor = currentUser.Name,
            // Whatever Oidc:RoleClaim names, on a token from either issuer. Empty on a local account
            // until an IUserRoleProvider says otherwise - see /api/admin below.
            currentUser.Roles,
            IsGateMaster = currentUser.IsInRole("gate-master"),
            // Anything else the token carries, without going back to HttpContext for it.
            SecondFactor = currentUser.FindClaim(ToamaisutaaDefaults.TwoFactorSourceClaim),
        },
    });
})
.WithName("Me");

// Named policy from Oidc:AdminRole. Local accounts carry no roles until an IUserRoleProvider says
// otherwise, so a locally issued token gets a 403 here - by design, and documented.
app.MapGet("/api/admin", () => "The gate master knows you. Come through.")
    .RequireAuthorization("Toamaisutaa.Admin")
    .WithName("Admin");

// Requires amr to contain mfa, so a password-only token gets a 403 here and a token from a completed
// challenge does not. This is what enforcement looks like in an application: a policy on a route.
app.MapGet("/api/sensitive", () => "Two locks, both opened. This is the inner room.")
    .RequireAuthorization("Toamaisutaa.TwoFactor")
    .WithName("Sensitive");

// Not "did you ever prove a second factor" but "did you prove one in the last two minutes". A
// device-trusted sign-in fails this until the user steps up, which is the whole distinction
// toa_2fa_at exists to make. Two minutes so the sample is quick to try; five is a saner default.
app.MapGet("/api/vault", () => "Nothing cached got you in here. That was a live code.")
    .RequireAuthorization("FreshSecondFactor")
    .WithName("Vault");

app.Run();

/// <summary>
/// Answers 401 when a token's security stamp is stale, for endpoints this application owns.
/// </summary>
/// <remarks>
/// A stale stamp means a credential changed after the token was issued - a password change, a
/// two-factor enrolment - so the token is genuinely no longer valid even though its signature and
/// expiry still are. That is an authentication failure, and a client seeing 401 with
/// <c>invalid_token</c> knows to refresh. Left unhandled it is a 500, which reads as a server fault
/// and gets escalated instead of retried.
/// </remarks>
internal sealed class StaleSecurityStampHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext context,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is not SecurityStampChangedException)
            return false;

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";

        await context.Response.WriteAsJsonAsync(
            new ErrorResponse { Error = "invalid_token", ErrorDescription = exception.Message },
            cancellationToken);

        return true;
    }
}

/// <summary>
/// Every measurement the <c>Toamaisutaa</c> meter publishes, read aloud into the log.
/// </summary>
/// <remarks>
/// A stand-in for an exporter, so the sample needs no metrics package to show the instruments
/// working. A real deployment points OpenTelemetry at the same meter by name and sends this
/// somewhere it can be graphed.
/// </remarks>
internal sealed class MetricsToTheLog(ILogger<MetricsToTheLog> logger) : IHostedService
{
    private readonly MeterListener _listener = new();

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == ToamaisutaaDefaults.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };

        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Write(instrument, value, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Write(instrument, value, tags));
        _listener.Start();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _listener.Dispose();
        return Task.CompletedTask;
    }

    private void Write(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var described = new StringBuilder();

        foreach (var tag in tags)
            described.Append(described.Length == 0 ? " " : ", ").Append(tag.Key).Append('=').Append(tag.Value);

        logger.LogInformation("{Instrument} {Value}{Tags}", instrument.Name, value, described.ToString());
    }
}

/// <summary>
/// Stands in for the audit table an application would keep - the gate master's ledger, in a sample
/// that has no table to write to.
/// </summary>
/// <remarks>
/// Deliberately dull, and it prints the same fields for every event: the point of a ledger is that
/// somebody can read a year of it. A real one switches on the event type for the extras -
/// <c>SignInFailed.Reason</c>, <c>SessionRevoked.Reason</c>, <c>TrustedDeviceRevoked.DeviceId</c> -
/// and writes a row rather than a line.
/// </remarks>
internal sealed class LoggingAuditSink(ILogger<LoggingAuditSink> logger) : IAuthenticationEventSink
{
    public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
    {
        logger.LogInformation(
            "Audit: {Kind} for user {UserId} at {OccurredAt} [{Methods}].",
            authenticationEvent.Kind,
            authenticationEvent.UserId,
            authenticationEvent.OccurredAt,
            string.Join(' ', authenticationEvent.AuthenticationMethods));

        return Task.CompletedTask;
    }
}

/// <summary>
/// Stands in for whatever the application already uses to send mail. The token is the only thing
/// here that matters, so it stays on its own and unadorned - paste it into /auth/password/reset.
/// </summary>
internal sealed class LoggingPasswordResetNotifier(ILogger<LoggingPasswordResetNotifier> logger) : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("No postman in this sample, so the gate master reads it aloud.");
        logger.LogWarning("PASSWORD RESET for {Email}: token {Token}", user.Email, resetToken);
        return Task.CompletedTask;
    }
}

/// <summary>
/// The same stand-in, for the address somebody is claiming. Note which address this is handed: it is
/// the one being verified, not the one the account currently has, and that is the entire mechanism -
/// paste the token into /auth/email/verify.
/// </summary>
internal sealed class LoggingEmailVerificationNotifier(ILogger<LoggingEmailVerificationNotifier> logger) : IEmailVerificationNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("The gate master reads this one aloud too, at the door it was addressed to.");
        logger.LogWarning("EMAIL VERIFICATION for {Email}: token {Token}", email, verificationToken);
        return Task.CompletedTask;
    }
}

/// <summary>
/// The same stand-in once more, for the token that IS a sign-in. Verify the address first at
/// /auth/email, or nothing is ever sent - paste the token into /auth/magic-link/verify and watch a
/// token pair come back with no password anywhere in it.
/// </summary>
internal sealed class LoggingMagicLinkNotifier(ILogger<LoggingMagicLinkNotifier> logger) : IMagicLinkNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("This one the gate master would rather whisper. Nothing else here opens a door by itself.");
        logger.LogWarning("MAGIC LINK for {Email}: token {Token}", user.Email, magicLinkToken);
        return Task.CompletedTask;
    }
}
