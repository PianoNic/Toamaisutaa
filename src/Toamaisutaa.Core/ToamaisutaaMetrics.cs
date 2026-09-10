using System.Diagnostics;
using System.Diagnostics.Metrics;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Every instrument this package publishes, on one <see cref="Meter"/> named
/// <see cref="ToamaisutaaDefaults.MeterName"/>.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Meter"/> is constructed here rather than taken from <c>IMeterFactory</c>, because
/// the factory lives in Microsoft.Extensions.Diagnostics and this project is the one that has to
/// stay usable from a console app holding nothing but the options and logging abstractions.
/// <see cref="Meter"/> itself is in the framework, so a meter costs no dependency and a factory
/// would cost one.
/// </para>
/// <para>
/// <b>No tag here carries a user id, an identifier, an address or anything derived from a
/// credential.</b> A time series is retained far longer than a log line and is grouped by whoever
/// reads the dashboard, so a dimension is a disclosure decision before it is a cardinality one.
/// Every tag below has a fixed, small set of values, and which account something happened to stays
/// in the logs where it can be aged out.
/// </para>
/// </remarks>
internal sealed class ToamaisutaaMetrics : IDisposable
{
    /// <summary>The verdict: an outcome for a sign-in, <c>succeeded</c> or <c>failed</c> elsewhere.</summary>
    private const string ResultTag = "result";

    /// <summary>The RFC 8176 methods the attempt ended up proving, space separated as the claim
    /// carries them.</summary>
    private const string MethodsTag = "amr";

    /// <summary>Which second factor was presented: <c>otp</c>, <c>recovery</c>, <c>device</c> or
    /// <c>passkey</c>.</summary>
    private const string SourceTag = "source";

    private const string Succeeded = "succeeded";
    private const string Failed = "failed";

    /// <summary>What <c>amr</c> says for an attempt that proved nothing and issued nothing.</summary>
    private const string NoMethods = "none";

    private readonly Meter _meter = new(ToamaisutaaDefaults.MeterName);

    private readonly Counter<long> _signIns;
    private readonly Counter<long> _lockouts;
    private readonly Counter<long> _twoFactorVerifications;
    private readonly Counter<long> _refreshTokenReuse;
    private readonly Counter<long> _rateLimitRejections;
    private readonly Histogram<double> _passwordVerification;

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
    }

    /// <summary>The meter these instruments belong to, so a test can listen to its own host's
    /// instruments rather than to every one in the process that shares the name.</summary>
    internal Meter Meter => _meter;

    /// <summary>
    /// One sign-in attempt, once it has a verdict.
    /// </summary>
    /// <param name="outcome">What the caller was told.</param>
    /// <param name="methods">
    /// The methods the attempt proved, or <see langword="null"/> when it issued nothing. Refusals
    /// share a single <c>amr</c> value rather than one per stage, so the series stays additive:
    /// summing over <c>amr</c> gives attempts, summing over <c>result</c> gives sign-ins by method.
    /// </param>
    internal void SignInCompleted(SignInOutcome outcome, IReadOnlyList<string>? methods) =>
        _signIns.Add(
            1,
            new KeyValuePair<string, object?>(ResultTag, Describe(outcome)),
            new KeyValuePair<string, object?>(MethodsTag, methods is null ? NoMethods : string.Join(' ', methods)));

    /// <summary>An account that was not locked a moment ago and is now.</summary>
    internal void LockedOut() => _lockouts.Add(1);

    /// <summary>
    /// One second factor checked. Only attempts that got as far as a real check are counted - a
    /// blank code, or a challenge against an enrolment that has since been deleted, never named a
    /// source, and inventing one for them would put attempts in the series that nobody made.
    /// </summary>
    internal void TwoFactorVerified(string source, bool succeeded) =>
        _twoFactorVerifications.Add(
            1,
            new KeyValuePair<string, object?>(SourceTag, source),
            new KeyValuePair<string, object?>(ResultTag, succeeded ? Succeeded : Failed));

    /// <summary>A refresh token presented after it was already exchanged. Never routine: each one
    /// means two parties held the chain.</summary>
    internal void RefreshTokenReuseDetected() => _refreshTokenReuse.Add(1);

    internal void RateLimitRejected() => _rateLimitRejections.Add(1);

    /// <summary>
    /// One key derivation on the sign-in path.
    /// </summary>
    /// <param name="startingTimestamp">A <see cref="Stopwatch.GetTimestamp"/> taken before the call.</param>
    /// <param name="result">
    /// What the hasher answered, or <see langword="null"/> for the equalising derivation against the
    /// dummy hash. Tagged rather than lumped together because the whole point of that derivation is
    /// that it costs what a real one costs, and this is the series that says whether it still does.
    /// </param>
    internal void PasswordVerified(long startingTimestamp, PasswordVerificationResult? result) =>
        _passwordVerification.Record(
            Stopwatch.GetElapsedTime(startingTimestamp).TotalSeconds,
            new KeyValuePair<string, object?>(ResultTag, Describe(result)));

    public void Dispose() => _meter.Dispose();

    /// <summary>
    /// Spelled out rather than taken from <see cref="Enum.ToString()"/>, so renaming an enum member
    /// cannot rename a series somebody has been graphing for a year. A value added to the enum and
    /// not added here reports under its member name until it is.
    /// </summary>
    private static string Describe(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.Succeeded => Succeeded,
        SignInOutcome.UnknownUser => "unknown_user",
        SignInOutcome.InvalidPassword => "invalid_password",
        SignInOutcome.LockedOut => "locked_out",
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
