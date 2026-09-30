using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The one place a second factor is checked, so sign-in and the enrolment endpoints accept a code
/// on identical terms.
/// </summary>
internal sealed class TwoFactorVerifier(
    ITwoFactorStore enrolments,
    IRecoveryCodeStore recoveryCodes,
    ITotpProvider totp,
    IRecoveryCodeProvider recoveryCodeProvider,
    ISecretProtector protector,
    ToamaisutaaMetrics metrics,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    TimeProvider timeProvider,
    ILogger<TwoFactorVerifier> logger)
{
    // beforeSpending runs after the code checks out and before it is spent, so a request that loses
    // its challenge to another has not already burned a recovery code.
    internal async Task<TwoFactorVerification> VerifyAsync(
        Guid userId,
        string code,
        bool requireConfirmed,
        CancellationToken cancellationToken,
        Func<Task<bool>>? beforeSpending = null)
    {
        if (string.IsNullOrWhiteSpace(code))
            return TwoFactorVerification.Failed;

        var enrolment = await enrolments.FindAsync(userId, cancellationToken);

        if (enrolment is null || (requireConfirmed && !enrolment.IsEnabled))
        {
            logger.LogWarning("Second factor refused for user {UserId}: no {State} enrolment.", userId, requireConfirmed ? "confirmed" : string.Empty);
            return TwoFactorVerification.Failed;
        }

        if (enrolment.IsEnabled && recoveryCodeProvider.LooksLikeRecoveryCode(code))
            return await RedeemRecoveryCodeAsync(userId, code, beforeSpending, cancellationToken);

        var secret = protector.Unprotect(new ProtectedSecret(
            enrolment.SecretCiphertext,
            enrolment.SecretNonce,
            enrolment.SecretTag,
            enrolment.EncryptionKeyVersion));

        try
        {
            var now = timeProvider.GetUtcNow();

            if (!totp.TryVerify(secret, code, now, enrolment.LastUsedStep, out var matchedStep))
            {
                logger.LogWarning("Second factor refused for user {UserId}: the code is wrong, expired or already used.", userId);
                metrics.TwoFactorVerified(TwoFactorSource.Otp, succeeded: false);
                return TwoFactorVerification.Failed;
            }

            if (beforeSpending is not null && !await beforeSpending())
                return TwoFactorVerification.Lost;

            // The step read above can be stale, so whoever records it first owns the code; everyone
            // else lost a race rather than sent a wrong code.
            if (!await enrolments.RecordUsedStepAsync(userId, matchedStep, cancellationToken))
            {
                logger.LogWarning("Second factor refused for user {UserId}: the code was used by another request first.", userId);
                metrics.TwoFactorVerified(TwoFactorSource.Otp, succeeded: false);
                return TwoFactorVerification.Lost;
            }

            metrics.TwoFactorVerified(TwoFactorSource.Otp, succeeded: true);

            if (protector.NeedsRewrap(enrolment.EncryptionKeyVersion))
                await RewrapAsync(enrolment, secret, cancellationToken);

            return new TwoFactorVerification
            {
                Succeeded = true,
                UsedRecoveryCode = false,
                RecoveryCodesRunningLow = false,
            };
        }
        finally
        {
            Array.Clear(secret);
        }
    }

    private async Task<TwoFactorVerification> RedeemRecoveryCodeAsync(
        Guid userId,
        string code,
        Func<Task<bool>>? beforeSpending,
        CancellationToken cancellationToken)
    {
        var normalized = RecoveryCodeProvider.Normalize(code);
        ToamaisutaaRecoveryCode? stored = null;

        foreach (var (hash, version) in RecoveryCodeHashes.Candidates(options.Value, normalized))
        {
            stored = await recoveryCodes.FindUnusedAsync(userId, hash, cancellationToken);

            // Only against a row actually stored that way, or a code is checked as something it never was.
            if (stored is not null && stored.HashVersion == version)
                break;

            stored = null;
        }

        if (stored is null)
        {
            logger.LogWarning("Second factor refused for user {UserId}: that recovery code is unknown or already spent.", userId);
            metrics.TwoFactorVerified(TwoFactorSource.Recovery, succeeded: false);
            return TwoFactorVerification.Failed;
        }

        if (beforeSpending is not null && !await beforeSpending())
            return TwoFactorVerification.Lost;

        // Conditional write: single use means one request, not every request that read it first.
        if (!await recoveryCodes.MarkConsumedAsync(stored.Id, timeProvider.GetUtcNow(), cancellationToken))
        {
            logger.LogWarning("Second factor refused for user {UserId}: that recovery code was spent by another request first.", userId);
            metrics.TwoFactorVerified(TwoFactorSource.Recovery, succeeded: false);
            return TwoFactorVerification.Lost;
        }

        metrics.TwoFactorVerified(TwoFactorSource.Recovery, succeeded: true);

        var remaining = await recoveryCodes.CountUnusedAsync(userId, cancellationToken);
        var low = remaining <= options.Value.RecoveryCodeLowWaterMark;

        logger.LogInformation(
            "User {UserId} signed in with a recovery code. {Remaining} unused code(s) remain{Warning}.",
            userId,
            remaining,
            low ? ", which is at or below the low-water mark" : string.Empty);

        return new TwoFactorVerification
        {
            Succeeded = true,
            UsedRecoveryCode = true,
            RecoveryCodesRunningLow = low,
        };
    }

    private async Task RewrapAsync(
        ToamaisutaaUserTwoFactor enrolment,
        byte[] secret,
        CancellationToken cancellationToken)
    {
        var rewrapped = protector.Protect(secret);

        // Lost to another request's rewrap or re-enrolment, which already left a current secret.
        if (!await enrolments.RewrapSecretAsync(
                enrolment.UserId,
                enrolment.EncryptionKeyVersion,
                rewrapped.Ciphertext,
                rewrapped.Nonce,
                rewrapped.Tag,
                rewrapped.KeyVersion,
                cancellationToken))
            return;

        logger.LogInformation(
            "Re-encrypted the two-factor secret for user {UserId} under key version {KeyVersion}.",
            enrolment.UserId,
            rewrapped.KeyVersion);
    }
}

internal readonly record struct TwoFactorVerification
{
    internal bool Succeeded { get; init; }

    internal bool UsedRecoveryCode { get; init; }

    internal bool RecoveryCodesRunningLow { get; init; }

    /// <summary>The code was right but another request spent it or its challenge first; not counted
    /// as a wrong code.</summary>
    internal bool LostRace { get; init; }

    internal static TwoFactorVerification Failed => new() { Succeeded = false };

    internal static TwoFactorVerification Lost => new() { Succeeded = false, LostRace = true };
}
