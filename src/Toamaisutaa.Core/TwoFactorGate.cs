using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// What the sign-in path is allowed to know about two-factor authentication.
/// </summary>
/// <remarks>
/// Everything is resolved through the provider rather than the constructor because password login
/// works perfectly well with no second factor registered at all, and a constructor dependency would
/// turn "did not call AddToamaisutaaTwoFactor" into an unresolvable-service crash at the first
/// sign-in. Absent, every method here answers "no".
/// </remarks>
internal sealed class TwoFactorGate(
    IServiceProvider provider,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    ILogger<TwoFactorGate> logger)
{
    /// <summary>
    /// True when this sign-in has to stop and ask for a second factor. Enrolment alone decides it:
    /// <see cref="TwoFactorEnforcement"/> governs who is pushed into enrolling, never whether an
    /// already-enrolled user is challenged. Someone who turned it on gets it in every mode.
    /// </summary>
    internal async Task<bool> RequiresChallengeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var enrolments = provider.GetService<ITwoFactorStore>();
        if (enrolments is null)
            return false;

        var enrolment = await enrolments.FindAsync(userId, cancellationToken);
        return enrolment is { ConfirmedAt: not null };
    }

    /// <summary>True when the user must enrol and has not, which the token says out loud so an
    /// application can let them reach the enrolment endpoints and nothing else.</summary>
    internal async Task<bool> MustEnrolAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (options.Value.Enforcement != TwoFactorEnforcement.RequiredForAll)
            return false;

        var enrolments = provider.GetService<ITwoFactorStore>();
        if (enrolments is null)
            return false;

        var enrolment = await enrolments.FindAsync(userId, cancellationToken);
        return enrolment is not { ConfirmedAt: not null };
    }

    internal async Task<TwoFactorChallenge> IssueChallengeAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        TwoFactorChallengePurpose purpose = TwoFactorChallengePurpose.SignIn,
        Guid? familyId = null)
    {
        var challenges = Required<ITwoFactorChallengeStore>();
        var lifetime = options.Value.ChallengeLifetime;
        var raw = SecureTokens.Create();

        await challenges.CreateAsync(
            new ToamaisutaaTwoFactorChallenge
            {
                Id = Guid.CreateVersion7(now),
                UserId = userId,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + lifetime,
                Purpose = purpose,
                FamilyId = familyId,
            },
            cancellationToken);

        return new TwoFactorChallenge(raw, (int)lifetime.TotalSeconds);
    }

    /// <summary>Spends a challenge, if it is the right kind and belongs to whoever is holding it.</summary>
    /// <param name="challengeToken">The raw challenge as the caller presented it.</param>
    /// <param name="code">A TOTP code or a recovery code.</param>
    /// <param name="now">The current instant, from the caller's clock.</param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <param name="purpose">
    /// What the redeeming endpoint is for. A challenge minted for the other one is refused, so a
    /// step-up challenge cannot be spent anonymously at the sign-in endpoint for a whole token pair.
    /// </param>
    /// <param name="familyId">
    /// The session presenting it, for <see cref="TwoFactorChallengePurpose.StepUp"/>. A challenge
    /// bound to a different family belongs to another of this user's sessions and is refused.
    /// </param>
    internal async Task<ChallengeRedemption> RedeemChallengeAsync(
        string challengeToken,
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        TwoFactorChallengePurpose purpose = TwoFactorChallengePurpose.SignIn,
        Guid? familyId = null)
    {
        var challenges = Required<ITwoFactorChallengeStore>();
        var stored = await challenges.FindByHashAsync(SecureTokens.HashToken(challengeToken), cancellationToken);

        if (stored is null)
            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge);

        // Same answer as a challenge that never existed, and on purpose: which ceremony a token
        // belongs to is not something an endpoint should confirm to whoever is holding it.
        if (stored.Purpose != purpose)
        {
            logger.LogWarning(
                "Two-factor challenge for user {UserId} was presented at the wrong endpoint: it is a {Actual} challenge and this is {Expected}.",
                stored.UserId,
                stored.Purpose,
                purpose);

            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge);
        }

        if (purpose == TwoFactorChallengePurpose.StepUp && stored.FamilyId != familyId)
        {
            logger.LogWarning(
                "Step-up challenge for user {UserId} was presented by a different session than the one that asked for it.",
                stored.UserId);

            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge);
        }

        if (stored.ConsumedAt is not null)
        {
            logger.LogWarning("Two-factor challenge for user {UserId} was presented again after being spent.", stored.UserId);
            return ChallengeRedemption.Failed(SignInOutcome.ChallengeAlreadyUsed);
        }

        if (stored.ExpiresAt <= now)
            return ChallengeRedemption.Failed(SignInOutcome.ChallengeExpired);

        // The challenge can outlive what it was challenging: disabling requires proof, so an
        // attacker cannot do this, but the account holder can - from a second device, while this
        // one still holds an unspent challenge. Checking the row is unconsumed is not enough.
        var enrolments = Required<ITwoFactorStore>();
        var enrolment = await enrolments.FindAsync(stored.UserId, cancellationToken);

        if (enrolment is not { ConfirmedAt: not null })
        {
            logger.LogWarning(
                "Two-factor challenge for user {UserId} refused: the enrolment it was issued against no longer exists.",
                stored.UserId);

            await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken);
            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge);
        }

        var verifier = Required<TwoFactorVerifier>();
        var verification = await verifier.VerifyAsync(stored.UserId, code, requireConfirmed: true, cancellationToken);

        if (!verification.Succeeded)
            return ChallengeRedemption.Failed(SignInOutcome.InvalidTwoFactorCode);

        // Spent the moment it works, and only when it works: consuming it on a wrong code would
        // mean one mistyped digit sends the person back to the login form.
        await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken);

        return new ChallengeRedemption
        {
            Outcome = SignInOutcome.Succeeded,
            UserId = stored.UserId,
            UsedRecoveryCode = verification.UsedRecoveryCode,
            RecoveryCodesRunningLow = verification.RecoveryCodesRunningLow,
        };
    }

    private T Required<T>() where T : notnull =>
        provider.GetService<T>()
            ?? throw new InvalidOperationException(
                $"A two-factor challenge is in play but no {typeof(T).Name} is registered. Call AddToamaisutaaTwoFactor(...).");
}

internal readonly record struct ChallengeRedemption
{
    internal SignInOutcome Outcome { get; init; }

    internal Guid UserId { get; init; }

    internal bool UsedRecoveryCode { get; init; }

    internal bool RecoveryCodesRunningLow { get; init; }

    internal static ChallengeRedemption Failed(SignInOutcome outcome) => new() { Outcome = outcome };
}
