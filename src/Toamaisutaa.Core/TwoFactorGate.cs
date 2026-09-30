using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Stores are resolved through the provider rather than the constructor so password login without
/// two-factor registered does not crash at the first sign-in.
/// </summary>
internal sealed class TwoFactorGate(
    IServiceProvider provider,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    ILogger<TwoFactorGate> logger)
{
    /// <summary>
    /// Enrolment alone decides it: <see cref="TwoFactorEnforcement"/> governs who must enrol, never
    /// whether an enrolled user is challenged.
    /// </summary>
    internal async Task<bool> RequiresChallengeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var enrolments = provider.GetService<ITwoFactorStore>();
        if (enrolments is null)
            return false;

        var enrolment = await enrolments.FindAsync(userId, cancellationToken);
        return enrolment is { ConfirmedAt: not null };
    }

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

    // Pass securityStamp as read before the first factor was checked; read here, it can be the stamp
    // of a reset that landed while the password was hashing.
    internal async Task<TwoFactorChallenge> IssueChallengeAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        TwoFactorChallengePurpose purpose = TwoFactorChallengePurpose.SignIn,
        Guid? familyId = null,
        string authenticationMethods = "",
        string? securityStamp = null)
    {
        var challenges = Required<ITwoFactorChallengeStore>();
        var lifetime = options.Value.ChallengeLifetime;
        var raw = SecureTokens.Create();
        securityStamp ??= (await Required<IUserStore>().FindByIdAsync(userId, cancellationToken))?.SecurityStamp;

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
                AuthenticationMethods = authenticationMethods,
                SecurityStamp = securityStamp,
            },
            cancellationToken);

        return new TwoFactorChallenge(raw, (int)lifetime.TotalSeconds);
    }

    /// <summary>
    /// A challenge minted for another purpose is refused, so a step-up challenge cannot be spent
    /// anonymously at the sign-in endpoint. <paramref name="refuseAttempt"/> runs before the code is
    /// checked so a locked account neither spends a recovery code nor learns whether a guess was
    /// right, and parallel guesses cannot all be checked before the lock lands.
    /// </summary>
    internal async Task<ChallengeRedemption> RedeemChallengeAsync(
        string challengeToken,
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        TwoFactorChallengePurpose purpose = TwoFactorChallengePurpose.SignIn,
        Guid? familyId = null,
        Func<Guid, Task<bool>>? refuseAttempt = null)
    {
        var challenges = Required<ITwoFactorChallengeStore>();
        var stored = await challenges.FindByHashAsync(SecureTokens.HashToken(challengeToken), cancellationToken);

        if (stored is null)
            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge);

        // Same answer as an unknown challenge, so the endpoint does not confirm which ceremony a
        // token belongs to.
        if (stored.Purpose != purpose)
        {
            logger.LogWarning(
                "Two-factor challenge for user {UserId} was presented at the wrong endpoint: it is a {Actual} challenge and this is {Expected}.",
                stored.UserId,
                stored.Purpose,
                purpose);

            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge, stored.UserId);
        }

        if (purpose == TwoFactorChallengePurpose.StepUp && stored.FamilyId != familyId)
        {
            logger.LogWarning(
                "Step-up challenge for user {UserId} was presented by a different session than the one that asked for it.",
                stored.UserId);

            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge, stored.UserId);
        }

        if (stored.ConsumedAt is not null)
        {
            logger.LogWarning("Two-factor challenge for user {UserId} was presented again after being spent.", stored.UserId);
            return ChallengeRedemption.Failed(SignInOutcome.ChallengeAlreadyUsed, stored.UserId);
        }

        if (stored.ExpiresAt <= now)
            return ChallengeRedemption.Failed(SignInOutcome.ChallengeExpired, stored.UserId);

        // A reset is the owner locking somebody out, so a sign-in they half finished before it must
        // not be finishable afterwards.
        if (stored.SecurityStamp is not null
            && await Required<IUserStore>().FindByIdAsync(stored.UserId, cancellationToken) is { } user
            && !string.Equals(user.SecurityStamp, stored.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Two-factor challenge for user {UserId} refused: it was issued before the account's credentials changed.",
                stored.UserId);

            await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken);
            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge, stored.UserId);
        }

        // The challenge can outlive its enrolment if the owner disabled two-factor from another
        // device, so an unconsumed row is not enough.
        var enrolments = Required<ITwoFactorStore>();
        var enrolment = await enrolments.FindAsync(stored.UserId, cancellationToken);

        if (enrolment is not { ConfirmedAt: not null })
        {
            logger.LogWarning(
                "Two-factor challenge for user {UserId} refused: the enrolment it was issued against no longer exists.",
                stored.UserId);

            await challenges.MarkConsumedAsync(stored.Id, now, cancellationToken);
            return ChallengeRedemption.Failed(SignInOutcome.InvalidChallenge, stored.UserId);
        }

        if (refuseAttempt is not null && await refuseAttempt(stored.UserId))
            return ChallengeRedemption.Failed(SignInOutcome.LockedOut, stored.UserId);

        var verifier = Required<TwoFactorVerifier>();

        // Spent only once the code checks out (a typo must not restart the login), only by whoever
        // wins the conditional write (one session per challenge), and before the code itself is
        // spent so losing the race does not also cost a recovery code.
        var verification = await verifier.VerifyAsync(
            stored.UserId,
            code,
            requireConfirmed: true,
            cancellationToken,
            beforeSpending: () => challenges.MarkConsumedAsync(stored.Id, now, cancellationToken));

        if (verification.LostRace)
        {
            logger.LogWarning("Two-factor challenge for user {UserId} was spent, or its code used, by another request first.", stored.UserId);
            return ChallengeRedemption.Failed(SignInOutcome.ChallengeAlreadyUsed, stored.UserId);
        }

        if (!verification.Succeeded)
            return ChallengeRedemption.Failed(SignInOutcome.InvalidTwoFactorCode, stored.UserId);

        return new ChallengeRedemption
        {
            Outcome = SignInOutcome.Succeeded,
            UserId = stored.UserId,
            UsedRecoveryCode = verification.UsedRecoveryCode,
            RecoveryCodesRunningLow = verification.RecoveryCodesRunningLow,
            AuthenticationMethods = stored.AuthenticationMethods,
            SecurityStamp = stored.SecurityStamp,
        };
    }

    internal Task<EnrolmentReservation> ReserveEnrolmentAttemptAsync(
        Guid userId,
        ToamaisutaaLocalLoginOptions localLogin,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Required<ITwoFactorStore>().ReserveAttemptAsync(userId, localLogin, now, cancellationToken);

    internal Task TryRefundEnrolmentAttemptAsync(Guid userId, EnrolmentReservation reservation, DateTimeOffset now, CancellationToken cancellationToken) =>
        Required<ITwoFactorStore>().TryRefundAttemptAsync(userId, reservation, now, cancellationToken);

    internal Task RegisterEnrolmentSuccessAsync(Guid userId, CancellationToken cancellationToken) =>
        Required<ITwoFactorStore>().RegisterSuccessAsync(userId, cancellationToken);

    private T Required<T>() where T : notnull =>
        provider.GetService<T>()
            ?? throw new InvalidOperationException(
                $"A two-factor challenge is in play but no {typeof(T).Name} is registered. Call AddToamaisutaaTwoFactor(...).");
}

internal readonly record struct ChallengeRedemption
{
    internal SignInOutcome Outcome { get; init; }

    internal Guid? UserId { get; init; }

    internal bool UsedRecoveryCode { get; init; }

    internal bool RecoveryCodesRunningLow { get; init; }

    /// <summary>Empty or absent means <c>pwd</c>, because older rows predate magic-link challenges.</summary>
    internal string? AuthenticationMethods { get; init; }

    /// <summary>The stamp the challenge was checked against; null on rows that predate it.</summary>
    internal string? SecurityStamp { get; init; }

    internal static ChallengeRedemption Failed(SignInOutcome outcome, Guid? userId = null) =>
        new() { Outcome = outcome, UserId = userId };
}
