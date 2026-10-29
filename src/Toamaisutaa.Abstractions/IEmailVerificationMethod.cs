namespace Toamaisutaa.Abstractions;

/// <summary>
/// How an address is proven when <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForSignIn"/>
/// holds a sign-in back: what is sent, and how what comes back is checked. The default mails a
/// six-digit code through <see cref="IEmailVerificationNotifier.SendCodeAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Register your own to prove the address some other way - a link, a message from another service -
/// and the endpoints, the challenge, lockout and what a proven address writes stay as they are. It is
/// resolved per request, so a scoped registration can use the request's unit of work.
/// </para>
/// <para>
/// Every proof checked here is already counted toward the account's lockout before
/// <see cref="VerifyAsync"/> is called, so an implementation need not throttle guesses itself. It does
/// have to retire what it issued once it has been used, and should give up on a proof that has been
/// guessed at too often.
/// </para>
/// </remarks>
public interface IEmailVerificationMethod
{
    /// <summary>
    /// What the challenge tells a client to ask for, as <c>method</c>: <c>code</c> for the default. A
    /// client picks the screen it shows from this, so keep it stable once shipped.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Sends a fresh proof to <see cref="EmailVerificationIssueRequest.Email"/>, retiring any earlier one,
    /// or declines because one went out too recently.
    /// </summary>
    /// <remarks>
    /// Called after a registration, after a right password for an unverified account, and when the
    /// person asks for another. Throwing is logged and the challenge is still handed back, so the
    /// person can ask again once delivery works.
    /// </remarks>
    Task<EmailVerificationIssueResult> IssueAsync(EmailVerificationIssueRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks a proof the person typed or followed. <see cref="EmailVerificationProofOutcome.Verified"/>
    /// must spend it, so the same proof cannot be presented twice.
    /// </summary>
    Task<EmailVerificationProofOutcome> VerifyAsync(EmailVerificationProofRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Who to send a proof to, and where.</summary>
public sealed record EmailVerificationIssueRequest
{
    public required ToamaisutaaUser User { get; init; }

    /// <summary>The credential's address, the one being proven. Send there, not to <see cref="ToamaisutaaUser.Email"/>.</summary>
    public required string Email { get; init; }
}

public sealed record EmailVerificationIssueResult
{
    public required EmailVerificationIssueOutcome Outcome { get; init; }

    /// <summary>With <see cref="EmailVerificationIssueOutcome.CoolingDown"/>, how long until another may be sent.</summary>
    public TimeSpan? RetryAfter { get; init; }

    public static EmailVerificationIssueResult Sent { get; } = new() { Outcome = EmailVerificationIssueOutcome.Sent };

    public static EmailVerificationIssueResult CoolingDown(TimeSpan retryAfter) =>
        new() { Outcome = EmailVerificationIssueOutcome.CoolingDown, RetryAfter = retryAfter };
}

public enum EmailVerificationIssueOutcome
{
    Sent,

    /// <summary>
    /// One went out too recently, so nothing was sent and the earlier proof still stands. A resend
    /// answers 429; a sign-in still hands back the challenge, which the earlier proof answers.
    /// </summary>
    CoolingDown,
}

/// <summary>What came back, for the address it was meant to prove.</summary>
public sealed record EmailVerificationProofRequest
{
    public required ToamaisutaaUser User { get; init; }

    /// <summary>The credential's address. A proof issued for any other address must not verify.</summary>
    public required string Email { get; init; }

    /// <summary>As the person typed it. The default ignores spaces and hyphens around the digits.</summary>
    public required string Proof { get; init; }
}

public enum EmailVerificationProofOutcome
{
    /// <summary>Right, and now spent.</summary>
    Verified,

    /// <summary>Wrong, and the proof can still be tried again.</summary>
    Invalid,

    /// <summary>Wrong, and that was the last try: the proof is spent. Ask for another.</summary>
    Exhausted,

    /// <summary>Nothing outstanding to compare against - expired, spent, or never sent. Ask for another.</summary>
    Expired,
}
