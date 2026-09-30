using System.Diagnostics;
using System.Diagnostics.Metrics;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The <see cref="Meter"/> is constructed rather than taken from <c>IMeterFactory</c>, which would
/// add a dependency Core must not have. No tag may carry a user id, address or anything derived from
/// a credential: time series outlive logs and are read by whoever sees the dashboard.
/// </summary>
internal sealed class ToamaisutaaMetrics : IDisposable
{
    private const string ResultTag = "result";

    private const string MethodsTag = "amr";

    private const string SourceTag = "source";

    private const string Succeeded = "succeeded";
    private const string Failed = "failed";

    private const string NoMethods = "none";

    private readonly Meter _meter = new(ToamaisutaaDefaults.MeterName);

    private readonly Counter<long> _signIns;
    private readonly Counter<long> _lockouts;
    private readonly Counter<long> _twoFactorVerifications;
    private readonly Counter<long> _refreshTokenReuse;
    private readonly Counter<long> _rateLimitRejections;
    private readonly Histogram<double> _passwordVerification;
    private readonly Counter<long> _mailRequestsDropped;

    public ToamaisutaaMetrics()
    {
        _signIns = _meter.CreateCounter<long>(
            "toamaisutaa.sign_in.attempts",
            unit: "{attempt}",
            description: "Local sign-in attempts that reached a verdict, by outcome and by the authentication methods proved.");

        _lockouts = _meter.CreateCounter<long>(
            "toamaisutaa.lockouts",
            unit: "{lockout}",
            description: "Accounts locked out by the failure counter reaching its threshold.");

        _twoFactorVerifications = _meter.CreateCounter<long>(
            "toamaisutaa.two_factor.verifications",
            unit: "{verification}",
            description: "Second factors presented for checking, by source and by whether they were accepted.");

        _refreshTokenReuse = _meter.CreateCounter<long>(
            "toamaisutaa.refresh_token.reuse_detections",
            unit: "{detection}",
            description: "Already-rotated refresh tokens presented again, each one revoking a family.");

        _rateLimitRejections = _meter.CreateCounter<long>(
            "toamaisutaa.rate_limit.rejections",
            unit: "{rejection}",
            description: "Requests the password endpoints' own limiter answered 429 to.");

        _passwordVerification = _meter.CreateHistogram<double>(
            "toamaisutaa.password.verification.duration",
            unit: "s",
            description: "Time spent in a password key derivation during sign-in.");

        _mailRequestsDropped = _meter.CreateCounter<long>(
            "toamaisutaa.mail_requests.dropped",
            unit: "{request}",
            description: "Reset and magic-link requests answered 204 but dropped because the mail queue was full.");
    }

    internal Meter Meter => _meter;

    /// <summary>Refusals share one <c>amr</c> value rather than one per stage so the series stays
    /// additive.</summary>
    internal void SignInCompleted(SignInOutcome outcome, IReadOnlyList<string>? methods) =>
        _signIns.Add(
            1,
            new KeyValuePair<string, object?>(ResultTag, Describe(outcome)),
            new KeyValuePair<string, object?>(MethodsTag, methods is null ? NoMethods : string.Join(' ', methods)));

    internal void LockedOut() => _lockouts.Add(1);

    internal void TwoFactorVerified(string source, bool succeeded) =>
        _twoFactorVerifications.Add(
            1,
            new KeyValuePair<string, object?>(SourceTag, source),
            new KeyValuePair<string, object?>(ResultTag, succeeded ? Succeeded : Failed));

    internal void RefreshTokenReuseDetected() => _refreshTokenReuse.Add(1);

    internal void RateLimitRejected() => _rateLimitRejections.Add(1);

    internal void MailRequestDropped() => _mailRequestsDropped.Add(1);

    /// <summary>A <see langword="null"/> result is the equalising dummy derivation, tagged apart so
    /// this series shows whether it still costs what a real one does.</summary>
    internal void PasswordVerified(long startingTimestamp, PasswordVerificationResult? result) =>
        _passwordVerification.Record(
            Stopwatch.GetElapsedTime(startingTimestamp).TotalSeconds,
            new KeyValuePair<string, object?>(ResultTag, Describe(result)));

    public void Dispose() => _meter.Dispose();

    /// <summary>
    /// Spelled out so renaming an enum member cannot rename a graphed series. Unknown user, wrong
    /// password and locked out share one value, or the scrape endpoint would reveal which guesses
    /// named a real account.
    /// </summary>
    private static string Describe(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.Succeeded => Succeeded,
        SignInOutcome.UnknownUser or SignInOutcome.InvalidPassword or SignInOutcome.LockedOut => "invalid_grant",
        SignInOutcome.NoLocalCredential => "no_local_credential",
        SignInOutcome.InvalidRefreshToken => "invalid_refresh_token",
        SignInOutcome.RefreshTokenExpired => "refresh_token_expired",
        SignInOutcome.RefreshTokenReused => "refresh_token_reused",
        SignInOutcome.RefreshTokenRevoked => "refresh_token_revoked",
        SignInOutcome.TwoFactorRequired => "two_factor_required",
        SignInOutcome.InvalidTwoFactorCode => "invalid_two_factor_code",
        SignInOutcome.InvalidChallenge => "invalid_challenge",
        SignInOutcome.ChallengeExpired => "challenge_expired",
        SignInOutcome.ChallengeAlreadyUsed => "challenge_already_used",
        SignInOutcome.SecurityStampChanged => "security_stamp_changed",
        SignInOutcome.SessionEnded => "session_ended",
        SignInOutcome.TwoFactorNotEnrolled => "two_factor_not_enrolled",
        SignInOutcome.NotALocalSession => "not_a_local_session",
        SignInOutcome.InvalidPasskey => "invalid_passkey",
        _ => outcome.ToString(),
    };

    private static string Describe(PasswordVerificationResult? result) => result switch
    {
        PasswordVerificationResult.Succeeded => Succeeded,
        PasswordVerificationResult.SucceededRehashNeeded => "rehash_needed",
        PasswordVerificationResult.Failed => Failed,
        _ => "no_credential",
    };
}
