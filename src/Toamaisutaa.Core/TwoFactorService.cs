using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
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
    TrustedDeviceGate trustedDevices,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    IServiceProvider provider,
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

    public async Task<TwoFactorEnrolmentStarted> BeginEnrolmentAsync(
        Guid userId,
        TwoFactorEnrolmentProof? proof = null,
        CancellationToken cancellationToken = default)
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

        await RequireEnrolmentProofAsync(userId, proof, now, cancellationToken);
        var secret = RandomNumberGenerator.GetBytes(settings.SecretSizeBytes);

        try
        {
            var wrapped = protector.Protect(secret);

            // Written onto the row already read: the store may be tracking it, and a second instance
            // with the same key throws. Its wrong-code count carries over, so restarting cannot wipe it.
            var enrolment = existing ?? new ToamaisutaaUserTwoFactor { UserId = userId, CreatedAt = now };

            enrolment.SecretCiphertext = wrapped.Ciphertext;
            enrolment.SecretNonce = wrapped.Nonce;
            enrolment.SecretTag = wrapped.Tag;
            enrolment.EncryptionKeyVersion = wrapped.KeyVersion;
            enrolment.ConfirmedAt = null;
            enrolment.LastUsedStep = null;
            enrolment.UpdatedAt = now;

            // Conditional on still being unconfirmed: the proof above takes long enough for another
            // request to confirm, and writing over that switched the second factor off.
            if (!await enrolments.ReplacePendingAsync(enrolment, cancellationToken))
            {
                throw new TwoFactorEnrolmentException(
                    "This account already has a confirmed second factor. Disable it before enrolling again, so that "
                    + "generating a new secret always requires proof of the old one.");
            }

            // Never log any part of the secret or URI: a log line outlives every rotation.
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

        if (timeProvider.GetUtcNow() - enrolment.UpdatedAt >= options.Value.EnrolmentLifetime)
        {
            logger.LogWarning("Two-factor confirmation refused for user {UserId}: the enrolment has expired.", userId);
            throw new TwoFactorEnrolmentException("This enrolment has expired. Begin again for a new secret, then confirm it.");
        }

        // Throttled like every other code, or a stolen token could guess its way to enabling
        // two-factor on an abandoned enrolment.
        var (_, refusal) = await VerifyProofAsync(userId, code, timeProvider.GetUtcNow(), cancellationToken, requireConfirmed: false);

        if (refusal == LockedOutRefusal)
            throw new TwoFactorEnrolmentException(refusal);

        if (refusal is not null)
        {
            // The superseded secret is gone, so a rewritten row is the only hint of a stale QR code.
            var superseded = enrolment.UpdatedAt > enrolment.CreatedAt;

            throw new TwoFactorEnrolmentException(superseded
                ? "That code is not right. If you scanned an earlier QR code, it is no longer the one on file - scan the current one and try again."
                : "That code is not right. Check that your device's clock is correct, then try the next code.");
        }

        var now = timeProvider.GetUtcNow();

        // Only the confirm columns, and only on the enrolment the code was checked against: a
        // whole-row write put back the used step read before the code was recorded, so the code
        // that confirmed worked once more at sign-in.
        if (!await enrolments.ConfirmPendingAsync(userId, enrolment.UpdatedAt, now, cancellationToken))
        {
            logger.LogWarning("Two-factor confirmation refused for user {UserId}: the enrolment changed while it was being confirmed.", userId);
            throw new TwoFactorEnrolmentException("This enrolment changed while it was being confirmed. Check the status, and begin again if it is not enabled.");
        }

        var codes = await IssueRecoveryCodesAsync(userId, now, cancellationToken);
        await BumpSecurityStampAsync(userId, "two-factor-enabled", now, cancellationToken);

        await events.PublishAsync(new TwoFactorEnrolled { OccurredAt = now, UserId = userId }, cancellationToken);

        logger.LogInformation("Two-factor authentication is now enabled for user {UserId}.", userId);

        return new TwoFactorEnrolmentCompleted { RecoveryCodes = codes };
    }

    public async Task<TwoFactorResult> DisableAsync(Guid userId, string proof, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        var (verification, refusal) = await VerifyProofAsync(userId, proof, now, cancellationToken);

        if (refusal is not null)
            return TwoFactorResult.Failure(refusal);

        await PublishRecoveryCodeUseAsync(userId, verification, now, cancellationToken);

        await recoveryCodes.ReplaceAllAsync(userId, [], cancellationToken);
        await enrolments.DeleteAsync(userId, cancellationToken);
        await BumpSecurityStampAsync(userId, "two-factor-disabled", now, cancellationToken);

        await events.PublishAsync(new TwoFactorDisabled { OccurredAt = now, UserId = userId }, cancellationToken);

        logger.LogWarning("Two-factor authentication was disabled for user {UserId}, and every local session was revoked.", userId);

        return new TwoFactorResult { Succeeded = true };
    }

    public async Task<TwoFactorEnrolmentCompleted> RegenerateRecoveryCodesAsync(Guid userId, string proof, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        var (verification, refusal) = await VerifyProofAsync(userId, proof, now, cancellationToken);

        if (refusal is not null)
            throw new TwoFactorEnrolmentException(refusal);

        await PublishRecoveryCodeUseAsync(userId, verification, now, cancellationToken);

        var codes = await IssueRecoveryCodesAsync(userId, now, cancellationToken);

        await BumpSecurityStampAsync(userId, "recovery-codes-regenerated", now, cancellationToken);

        logger.LogInformation("Regenerated recovery codes for user {UserId}; every previous code is now dead.", userId);

        return new TwoFactorEnrolmentCompleted { RecoveryCodes = codes };
    }

    /// <summary>
    /// A bearer token alone must not be enough, or one lifted from a log could enrol and lock the
    /// owner out.
    /// </summary>
    private async Task RequireEnrolmentProofAsync(
        Guid userId,
        TwoFactorEnrolmentProof? proof,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // A time ahead of now is a clock problem, not a fresh sign-in.
        if (proof?.AuthenticatedAt is { } at && at <= now && now - at <= options.Value.EnrolmentProofWindow)
            return;

        var passwords = provider.GetService<IPasswordCredentialStore>();
        var credential = passwords is null ? null : await passwords.FindByUserIdAsync(userId, cancellationToken);
        var hasher = provider.GetService<IPasswordHasher>();

        if (credential is null || hasher is null || string.IsNullOrEmpty(proof?.CurrentPassword))
        {
            logger.LogWarning(
                "Two-factor enrolment refused for user {UserId}: no current password and no recent sign-in.",
                userId);

            throw new TwoFactorEnrolmentException(credential is null
                ? "Enrolling needs a recent sign-in. Sign in again, then enrol while that sign-in is fresh."
                : "Enrolling needs your current password. Send currentPassword.");
        }

        var refusal = await passwords!.CheckCurrentPasswordAsync(
            credential,
            proof.CurrentPassword,
            hasher,
            events,
            provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value,
            logger,
            "Two-factor enrolment",
            now,
            cancellationToken);

        if (refusal is not null)
            throw new TwoFactorEnrolmentException(refusal);
    }

    /// <summary>
    /// Counted like a wrong code at sign-in, or a stolen access token is an unthrottled six-digit
    /// oracle whose prize is the second factor itself.
    /// </summary>
    private async Task<(TwoFactorVerification Verification, string? Refusal)> VerifyProofAsync(
        Guid userId,
        string proof,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool requireConfirmed = true)
    {
        var passwords = provider.GetService<IPasswordCredentialStore>();
        var credential = passwords is null ? null : await passwords.FindByUserIdAsync(userId, cancellationToken);

        var localLogin = provider.GetService<IOptions<ToamaisutaaLocalLoginOptions>>()?.Value ?? new ToamaisutaaLocalLoginOptions();

        // Reserved before the code is checked, so a locked account neither spends a recovery code nor
        // learns whether a guess was right, and parallel guesses cannot each find it open. Accounts
        // without a password count on the enrolment instead.
        bool allowed;
        DateTimeOffset? lockedUntil;
        AttemptReservation? reservation = null;
        EnrolmentReservation? enrolmentReservation = null;

        if (credential is not null)
        {
            reservation = await passwords!.ReserveAttemptAsync(credential, localLogin, now, cancellationToken);
            credential = reservation.Value.Credential;
            allowed = reservation.Value.Allowed;
            lockedUntil = reservation.Value.LockedByThisAttempt ? credential.LockedOutUntil : null;
        }
        else
        {
            enrolmentReservation = await enrolments.ReserveAttemptAsync(userId, localLogin, now, cancellationToken);
            (allowed, lockedUntil) = (enrolmentReservation.Value.Allowed, enrolmentReservation.Value.LockedUntil);
        }

        if (!allowed)
        {
            logger.LogWarning("Two-factor proof refused for user {UserId}: locked out.", userId);

            await PublishWrongProofAsync(userId, SignInOutcome.LockedOut, now, cancellationToken);
            return (default, LockedOutRefusal);
        }

        var verification = await verifier.VerifyAsync(userId, proof, requireConfirmed, cancellationToken);

        if (verification.Succeeded)
        {
            // Only this reservation is refunded, never the whole count, because the credential's count
            // also holds wrong passwords.
            if (reservation is { } spent)
                await passwords!.RefundAsync(spent, now, cancellationToken);
            else
                await enrolments.RegisterSuccessAsync(userId, cancellationToken);

            return (verification, null);
        }

        // Right code, but another request spent it first: not a wrong guess, so it is given back.
        if (verification.LostRace)
        {
            if (reservation is { } lost)
                await passwords!.TryRefundAsync(lost, now, cancellationToken);
            else if (enrolmentReservation is { } lostOnEnrolment)
                await enrolments.TryRefundAttemptAsync(userId, lostOnEnrolment, now, cancellationToken);

            return (verification, "That code was just used by another request. Wait for the next one.");
        }

        if (credential is null)
        {
            logger.LogWarning("Two-factor proof refused for user {UserId}: wrong code{Locked}.", userId, lockedUntil is not null ? "; now locked out" : string.Empty);
        }
        else
        {
            logger.LogWarning(
                "Two-factor proof refused for user {UserId}: wrong code. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
                userId,
                credential.FailedAttemptCount,
                credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);
        }

        // Published once, by the attempt that set it, for either counter, or passwordless lockouts
        // are invisible to audit sinks.
        if (lockedUntil is { } lockedOutUntil)
        {
            provider.GetService<ToamaisutaaMetrics>()?.LockedOut();

            await events.PublishAsync(
                new AccountLockedOut { OccurredAt = now, UserId = userId, LockedOutUntil = lockedOutUntil },
                cancellationToken);
        }

        await PublishWrongProofAsync(userId, SignInOutcome.InvalidTwoFactorCode, now, cancellationToken);
        return (verification, "That code is not right.");
    }

    private const string LockedOutRefusal = "Too many wrong codes. Try again later.";

    private Task PublishWrongProofAsync(Guid userId, SignInOutcome reason, DateTimeOffset now, CancellationToken cancellationToken) =>
        events.PublishAsync(new TwoFactorFailed { OccurredAt = now, UserId = userId, Reason = reason }, cancellationToken);

    private async Task<IReadOnlyList<string>> IssueRecoveryCodesAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var plaintext = recoveryCodeProvider.Generate(options.Value.RecoveryCodeCount);

        // Replaces the whole set, or a stolen printout stays good forever.
        await recoveryCodes.ReplaceAllAsync(
            userId,
            [.. plaintext.Select(code => new ToamaisutaaRecoveryCode
            {
                Id = Guid.CreateVersion7(now),
                UserId = userId,
                CodeHash = RecoveryCodeHashes.Hash(options.Value, RecoveryCodeProvider.Normalize(code)),
                HashVersion = RecoveryCodeHashes.KeyedVersion,
                CreatedAt = now,
            })],
            cancellationToken);

        return plaintext;
    }

    /// <summary>
    /// Devices are revoked explicitly because the stamp check is lazy and would leave dead devices
    /// looking live in the user's list.
    /// </summary>
    private async Task BumpSecurityStampAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await refreshTokens.RevokeAllForUserAsync(userId, reason, now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, reason, now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked { OccurredAt = now, UserId = userId, Reason = reason },
            cancellationToken);
    }

    private async Task PublishRecoveryCodeUseAsync(
        Guid userId,
        TwoFactorVerification verification,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!verification.UsedRecoveryCode)
            return;

        await events.PublishAsync(
            new RecoveryCodeUsed { OccurredAt = now, UserId = userId, RunningLow = verification.RecoveryCodesRunningLow },
            cancellationToken);
    }
}
