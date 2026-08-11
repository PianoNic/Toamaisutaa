using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class TwoFactorService(
    ITwoFactorStore enrolments,
    IRecoveryCodeStore recoveryCodes,
    IUserStore users,
    IRefreshTokenStore refreshTokens,
    ITotpProvider totp,
    IRecoveryCodeProvider recoveryCodeProvider,
    ISecretProtector protector,
    TwoFactorVerifier verifier,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    TimeProvider timeProvider,
    ILogger<TwoFactorService> logger) : ITwoFactorService
{
    public async Task<TwoFactorStatus> GetStatusAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var enrolment = await enrolments.FindAsync(userId, cancellationToken);

        if (enrolment is null)
            return new TwoFactorStatus(Enabled: false, EnrolmentPending: false, RecoveryCodesRemaining: 0);

        return new TwoFactorStatus(
            Enabled: enrolment.IsEnabled,
            EnrolmentPending: !enrolment.IsEnabled,
            RecoveryCodesRemaining: enrolment.IsEnabled ? await recoveryCodes.CountUnusedAsync(userId, cancellationToken) : 0);
    }

    public async Task<TwoFactorEnrolmentStarted> BeginEnrolmentAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
            ?? throw new InvalidOperationException($"User {userId} does not exist.");

        var existing = await enrolments.FindAsync(userId, cancellationToken);

        if (existing is { ConfirmedAt: not null })
        {
            throw new TwoFactorEnrolmentException(
                "This account already has a confirmed second factor. Disable it before enrolling again, so that "
                + "generating a new secret always requires proof of the old one.");
        }

        var settings = options.Value;
        var now = timeProvider.GetUtcNow();
        var secret = RandomNumberGenerator.GetBytes(settings.SecretSizeBytes);

        try
        {
            var wrapped = protector.Protect(secret);

            // The second call replaces the first, so a page reload does not leave a trail of live
            // unconfirmed secrets. It also means a user who scanned the earlier QR code is now
            // holding a dead one, which is what ConfirmEnrolmentAsync's hint is for.
            await enrolments.UpsertAsync(
                new ToamaisutaaUserTwoFactor
                {
                    UserId = userId,
                    SecretCiphertext = wrapped.Ciphertext,
                    SecretNonce = wrapped.Nonce,
                    SecretTag = wrapped.Tag,
                    EncryptionKeyVersion = wrapped.KeyVersion,
                    ConfirmedAt = null,
                    LastUsedStep = null,
                    CreatedAt = existing?.CreatedAt ?? now,
                    UpdatedAt = now,
                },
                cancellationToken);

            // Deliberately says nothing about what was handed out. This response carries the secret
            // in plaintext, and a log line that quoted any part of it would outlive every rotation.
            logger.LogInformation("Started two-factor enrolment for user {UserId}. Nothing is enabled until it is confirmed.", userId);

            var issuer = settings.Issuer ?? "Toamaisutaa";
            var account = user.UserName ?? user.Email ?? userId.ToString();

            return new TwoFactorEnrolmentStarted
            {
                Secret = totp.Encode(secret),
                Uri = totp.BuildUri(secret, issuer, account),
            };
        }
        finally
        {
            Array.Clear(secret);
        }
    }

    public async Task<TwoFactorEnrolmentCompleted> ConfirmEnrolmentAsync(Guid userId, string code, CancellationToken cancellationToken = default)
    {
        var enrolment = await enrolments.FindAsync(userId, cancellationToken)
            ?? throw new TwoFactorEnrolmentException("There is no enrolment to confirm. Start one first.");

        if (enrolment.IsEnabled)
            throw new TwoFactorEnrolmentException("This account already has a confirmed second factor.");

        var verification = await verifier.VerifyAsync(userId, code, requireConfirmed: false, cancellationToken);

        if (!verification.Succeeded)
        {
            // We cannot tell a wrong code from a stale one - the superseded secret is gone, so
            // there is nothing left to check the code against. What we can tell is that the row was
            // rewritten at least once, which makes the stale-QR-code case worth mentioning.
            var superseded = enrolment.UpdatedAt > enrolment.CreatedAt;

            throw new TwoFactorEnrolmentException(superseded
                ? "That code is not right. If you scanned an earlier QR code, it is no longer the one on file - scan the current one and try again."
                : "That code is not right. Check that your device's clock is correct, then try the next code.");
        }

        var now = timeProvider.GetUtcNow();

        enrolment.ConfirmedAt = now;
        enrolment.UpdatedAt = now;
        await enrolments.UpsertAsync(enrolment, cancellationToken);

        var codes = await IssueRecoveryCodesAsync(userId, now, cancellationToken);
        await BumpSecurityStampAsync(userId, "two-factor-enabled", now, cancellationToken);

        logger.LogInformation("Two-factor authentication is now enabled for user {UserId}.", userId);

        return new TwoFactorEnrolmentCompleted { RecoveryCodes = codes };
    }

    public async Task<TwoFactorResult> DisableAsync(Guid userId, string proof, CancellationToken cancellationToken = default)
    {
        var verification = await verifier.VerifyAsync(userId, proof, requireConfirmed: true, cancellationToken);

        if (!verification.Succeeded)
            return TwoFactorResult.Failure("That code is not right.");

        var now = timeProvider.GetUtcNow();

        await recoveryCodes.ReplaceAllAsync(userId, [], cancellationToken);
        await enrolments.DeleteAsync(userId, cancellationToken);
        await BumpSecurityStampAsync(userId, "two-factor-disabled", now, cancellationToken);

        logger.LogWarning("Two-factor authentication was disabled for user {UserId}, and every local session was revoked.", userId);

        return new TwoFactorResult { Succeeded = true };
    }

    public async Task<TwoFactorEnrolmentCompleted> RegenerateRecoveryCodesAsync(Guid userId, string proof, CancellationToken cancellationToken = default)
    {
        var verification = await verifier.VerifyAsync(userId, proof, requireConfirmed: true, cancellationToken);

        if (!verification.Succeeded)
            throw new TwoFactorEnrolmentException("That code is not right.");

        var now = timeProvider.GetUtcNow();
        var codes = await IssueRecoveryCodesAsync(userId, now, cancellationToken);

        await BumpSecurityStampAsync(userId, "recovery-codes-regenerated", now, cancellationToken);

        logger.LogInformation("Regenerated recovery codes for user {UserId}; every previous code is now dead.", userId);

        return new TwoFactorEnrolmentCompleted { RecoveryCodes = codes };
    }

    private async Task<IReadOnlyList<string>> IssueRecoveryCodesAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var plaintext = recoveryCodeProvider.Generate(options.Value.RecoveryCodeCount);

        // Replaces the whole set rather than adding to it: regeneration has to invalidate every
        // previous code, or a stolen printout stays good forever.
        await recoveryCodes.ReplaceAllAsync(
            userId,
            [.. plaintext.Select(code => new ToamaisutaaRecoveryCode
            {
                Id = Guid.CreateVersion7(now),
                UserId = userId,
                CodeHash = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(code)),
                CreatedAt = now,
            })],
            cancellationToken);

        return plaintext;
    }

    private async Task BumpSecurityStampAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await refreshTokens.RevokeAllForUserAsync(userId, reason, now, cancellationToken);
    }
}
