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
    IOptions<ToamaisutaaTwoFactorOptions> options,
    TimeProvider timeProvider,
    ILogger<TwoFactorVerifier> logger)
{
    internal async Task<TwoFactorVerification> VerifyAsync(
        Guid userId,
        string code,
        bool requireConfirmed,
        CancellationToken cancellationToken)
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
            return await RedeemRecoveryCodeAsync(userId, code, cancellationToken);

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
                return TwoFactorVerification.Failed;
            }

            await enrolments.RecordUsedStepAsync(userId, matchedStep, cancellationToken);

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

    private async Task<TwoFactorVerification> RedeemRecoveryCodeAsync(Guid userId, string code, CancellationToken cancellationToken)
    {
        var hash = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(code));
        var stored = await recoveryCodes.FindUnusedAsync(userId, hash, cancellationToken);

        if (stored is null)
        {
            logger.LogWarning("Second factor refused for user {UserId}: that recovery code is unknown or already spent.", userId);
            return TwoFactorVerification.Failed;
        }

        await recoveryCodes.MarkConsumedAsync(stored.Id, timeProvider.GetUtcNow(), cancellationToken);

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

    internal static TwoFactorVerification Failed => new() { Succeeded = false };
}
