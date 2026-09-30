using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The one place a second factor is checked. Shared by the sign-in path, which is finishing a
/// challenge, and by the enrolment endpoints, which demand proof before they will switch anything
/// off - so a code accepted in one is accepted on identical terms in the other.
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
    // beforeSpending is called once the code has checked out and before it is spent, and nothing is
    // spent when it answers false. The sign-in path spends its challenge there, so a request that
    // loses the challenge to another one has not already burned a recovery code for nothing.
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

        // Recovery codes only exist once the enrolment is confirmed, so an unconfirmed one has
        // nothing to fall back to and must be proved with the authenticator itself.
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

            // The step read above can be stale by now. Whoever records it first owns the code; for
            // everyone else it is refused - as a race lost, not a wrong code, since it was right.
            if (!await enrolments.RecordUsedStepAsync(userId, matchedStep, cancellationToken))
            {
                logger.LogWarning("Second factor refused for user {UserId}: the code was used by another request first.", userId);
                metrics.TwoFactorVerified(TwoFactorSource.Otp, succeeded: false);
                return TwoFactorVerification.Lost;
            }

            metrics.TwoFactorVerified(TwoFactorSource.Otp, succeeded: true);

            // Kept in sync on the tracked object too, or the rewrap below writes the whole row back
            // with the step it had before this code was accepted and undoes the replay protection.
            enrolment.LastUsedStep = matchedStep;

            if (protector.NeedsRewrap(enrolment.EncryptionKeyVersion))
                await RewrapAsync(enrolment, secret, now, cancellationToken);

            return new TwoFactorVerification
            {
                Succeeded = true,
                UsedRecoveryCode = false,
                RecoveryCodesRunningLow = false,
            };
        }
        finally
        {
            // The plaintext secret existed in this method and nowhere else. Do not leave it for the
            // garbage collector to hand to whatever allocates next.
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

            // Only against a row actually stored that way. A keyed row matching the unkeyed hash
            // would mean the code had been checked as something it never was.
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

        // Single use means one request, not one per request that read it before either spent it.
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

    /// <summary>
    /// Re-encrypts under the current key while the plaintext is already in hand, which is the only
    /// moment it is available without a second decryption. Same lazy rotation as the pepper.
    /// </summary>
    private async Task RewrapAsync(
        ToamaisutaaUserTwoFactor enrolment,
        byte[] secret,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var rewrapped = protector.Protect(secret);

        enrolment.SecretCiphertext = rewrapped.Ciphertext;
        enrolment.SecretNonce = rewrapped.Nonce;
        enrolment.SecretTag = rewrapped.Tag;
        enrolment.EncryptionKeyVersion = rewrapped.KeyVersion;
        enrolment.UpdatedAt = now;

        await enrolments.UpsertAsync(enrolment, cancellationToken);

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

    /// <summary>The code was right, and another request spent it - or the challenge it came with -
    /// first. Not a wrong code, and not counted as one.</summary>
    internal bool LostRace { get; init; }

    internal static TwoFactorVerification Failed => new() { Succeeded = false };

    internal static TwoFactorVerification Lost => new() { Succeeded = false, LostRace = true };
}
