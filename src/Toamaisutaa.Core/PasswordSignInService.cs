using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class PasswordSignInService(
    IPasswordCredentialStore credentials,
    IUserStore users,
    IRefreshTokenStore refreshTokens,
    IMagicLinkTokenStore magicLinkTokens,
    IPasswordHasher hasher,
    IAccessTokenIssuer accessTokens,
    IUserRoleProvider roles,
    LocalSessionIssuer sessions,
    DummyPasswordHash dummy,
    TwoFactorGate twoFactor,
    TrustedDeviceGate trustedDevices,
    ToamaisutaaMetrics metrics,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<PasswordSignInService> logger) : IPasswordSignInService
{
    public async Task<SignInResult> SignInAsync(PasswordSignInRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var password = request.Password;

        var now = timeProvider.GetUtcNow();
        var credential = await credentials.FindByIdentifierAsync(Normalizer.Normalize(request.Identifier), cancellationToken);

        if (credential is null)
        {
            // Timing equaliser: pay what a real account would, so the clock does not reveal existence.
            VerifyDummy(password);
            logger.LogInformation("Sign-in refused: no local credential matches the identifier presented.");

            // The tried identifier is deliberately not recorded: users sometimes type their password
            // into the user name box.
            await events.PublishAsync(new SignInFailed { OccurredAt = now, Reason = SignInOutcome.UnknownUser }, cancellationToken);

            return Refused(SignInOutcome.UnknownUser);
        }

        // Read before the password is checked, or a reset landing while the hash runs hands its fresh
        // stamp to a sign-in with the old password.
        var user = await users.FindByIdAsync(credential.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Credential for user {credential.UserId} has no user row.");

        // Counted before the hash is checked, so parallel guesses cannot each find the account open.
        var reservation = await credentials.ReserveAttemptAsync(credential, options.Value, now, cancellationToken);
        credential = reservation.Credential;

        if (!reservation.Allowed)
        {
            VerifyDummy(password);
            logger.LogWarning(
                "Sign-in refused for user {UserId}: locked out until {LockedOutUntil}.",
                credential.UserId,
                credential.LockedOutUntil);

            await events.PublishAsync(
                new SignInFailed { OccurredAt = now, UserId = credential.UserId, Reason = SignInOutcome.LockedOut },
                cancellationToken);

            return Refused(SignInOutcome.LockedOut);
        }

        var startedVerifying = Stopwatch.GetTimestamp();
        var verification = hasher.Verify(password, credential.PasswordHash);
        metrics.PasswordVerified(startedVerifying, verification);

        if (verification == PasswordVerificationResult.Failed)
        {
            // Already counted by the reservation; only the attempt that set the lock reports it.
            if (reservation.LockedByThisAttempt && credential.LockedOutUntil is { } lockedOutUntil)
            {
                metrics.LockedOut();

                await events.PublishAsync(
                    new AccountLockedOut { OccurredAt = now, UserId = credential.UserId, LockedOutUntil = lockedOutUntil },
                    cancellationToken);
            }

            logger.LogWarning(
                "Sign-in refused for user {UserId}: wrong password. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
                credential.UserId,
                credential.FailedAttemptCount,
                credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);

            await events.PublishAsync(
                new SignInFailed { OccurredAt = now, UserId = credential.UserId, Reason = SignInOutcome.InvalidPassword },
                cancellationToken);

            return Refused(SignInOutcome.InvalidPassword);
        }

        // Held here rather than set on the tracked credential, where any later SaveChanges would
        // flush it unguarded over whatever had moved since.
        var rehash = verification == PasswordVerificationResult.SucceededRehashNeeded
            ? new Rehash(credential.PasswordHash, hasher.Hash(password))
            : (Rehash?)null;

        if (rehash is not null)
            logger.LogInformation("Rehashed the stored password for user {UserId} with current parameters.", credential.UserId);

        // The device token is consulted only after lockout and the password, or holding one would
        // skip lockout and reveal device trust to somebody without the password.
        if (await twoFactor.RequiresChallengeAsync(user.Id, cancellationToken))
        {
            var trust = await trustedDevices.TryRedeemAsync(user, request.DeviceToken, now, cancellationToken);

            if (!string.IsNullOrWhiteSpace(request.DeviceToken))
                metrics.TwoFactorVerified(TwoFactorSource.Device, trust.Trusted);

            if (!trust.Trusted)
            {
                // Only this reservation is refunded; clearing the count would let a password holder
                // guess codes indefinitely by signing in again every few attempts.
                credential = await credentials.RefundAsync(reservation, now, cancellationToken);

                if (rehash is { } pending)
                {
                    await credentials.UpdateAsync(
                        credential,
                        current =>
                        {
                            pending.ApplyTo(current);
                            current.UpdatedAt = now;
                        },
                        cancellationToken);
                }

                var challenge = await twoFactor.IssueChallengeAsync(
                    user.Id,
                    now,
                    cancellationToken,
                    authenticationMethods: "pwd",
                    securityStamp: user.SecurityStamp);

                logger.LogInformation("Password accepted for user {UserId}; a second factor is required.", user.Id);

                metrics.SignInCompleted(SignInOutcome.TwoFactorRequired, methods: null);

                return new SignInResult { Outcome = SignInOutcome.TwoFactorRequired, Challenge = challenge };
            }

            if (!await credentials.TryRegisterSuccessAsync(credential, reservation, now, cancellationToken, rehash))
                return await LockedWhileVerifyingAsync(user.Id, now, cancellationToken);

            logger.LogInformation("Sign-in succeeded for user {UserId} with a cached second factor.", user.Id);

            // No otp: nothing one-time was presented now; toa_2fa_at says when it was.
            string[] cached = ["pwd", ToamaisutaaDefaults.MultiFactorMethod];

            var cachedResult = await IssueAsync(
                user,
                familyId: null,
                familyStartedAt: null,
                methods: cached,
                recoveryCodesRunningLow: false,
                twoFactorSource: TwoFactorSource.Device,
                secondFactorAt: trust.SecondFactorAt,
                trustedDevice: trust.RotatedToken,
                newSignIn: true,
                client: ClientMetadata.Describe(request.UserAgent, request.IpAddress, options.Value.IpAddressStorage),
                now,
                cancellationToken);

            metrics.SignInCompleted(cachedResult.Outcome, cached);
            return cachedResult;
        }

        if (!await credentials.TryRegisterSuccessAsync(credential, reservation, now, cancellationToken, rehash))
            return await LockedWhileVerifyingAsync(user.Id, now, cancellationToken);

        logger.LogInformation("Sign-in succeeded for user {UserId}.", user.Id);

        string[] passwordOnly = ["pwd"];

        var result = await IssueAsync(
            user,
            familyId: null,
            familyStartedAt: null,
            methods: passwordOnly,
            recoveryCodesRunningLow: false,
            twoFactorSource: null,
            secondFactorAt: null,
            trustedDevice: null,
            newSignIn: true,
            client: ClientMetadata.Describe(request.UserAgent, request.IpAddress, options.Value.IpAddressStorage),
            now,
            cancellationToken);

        metrics.SignInCompleted(result.Outcome, passwordOnly);
        return result;
    }

    public async Task<SignInResult> VerifyTwoFactorAsync(TwoFactorSignInRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();

        // Null for an account with no password, whose count lives on the enrolment.
        ToamaisutaaPasswordCredential? credential = null;
        AttemptReservation? reservation = null;
        EnrolmentReservation? enrolmentReservation = null;

        var redemption = await twoFactor.RedeemChallengeAsync(
            request.ChallengeToken,
            request.Code,
            now,
            cancellationToken,
            refuseAttempt: async userId =>
            {
                credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

                // Reserved before the code is checked, or one challenge takes unlimited guesses.
                if (credential is not null)
                {
                    reservation = await credentials.ReserveAttemptAsync(credential, options.Value, now, cancellationToken);
                    credential = reservation.Value.Credential;
                    return !reservation.Value.Allowed;
                }

                enrolmentReservation = await twoFactor.ReserveEnrolmentAttemptAsync(userId, options.Value, now, cancellationToken);
                return !enrolmentReservation.Value.Allowed;
            });

        if (redemption.Outcome != SignInOutcome.Succeeded)
        {
            if (redemption.Outcome == SignInOutcome.InvalidTwoFactorCode && reservation is { } reserved)
                await ReportWrongCodeAsync(reserved, "Sign-in", now, cancellationToken);
            else if (redemption.Outcome == SignInOutcome.InvalidTwoFactorCode && enrolmentReservation?.LockedUntil is { } until)
                await ReportLockedOutAsync(redemption.UserId!.Value, until, now, cancellationToken);
            else
                await GiveBackLostRaceAsync(redemption.Outcome, redemption.UserId, reservation, enrolmentReservation, now, cancellationToken);

            await events.PublishAsync(
                new TwoFactorFailed { OccurredAt = now, UserId = redemption.UserId, Reason = redemption.Outcome },
                cancellationToken);

            return Refused(redemption.Outcome);
        }

        // The count comes off only when a sign-in has finished, never after a first factor that
        // still owes a second.
        if (credential is not null)
            await credentials.RegisterSuccessAsync(credential, now, cancellationToken);
        else
            await twoFactor.RegisterEnrolmentSuccessAsync(redemption.UserId!.Value, cancellationToken);

        var user = await users.FindByIdAsync(redemption.UserId!.Value, cancellationToken)
            ?? throw new InvalidOperationException($"Challenge points at user {redemption.UserId}, which does not exist.");

        // A recovery code means the authenticator is gone, so devices are revoked explicitly; bumping
        // the stamp would revoke the session being established.
        if (redemption.UsedRecoveryCode)
        {
            await events.PublishAsync(
                new RecoveryCodeUsed { OccurredAt = now, UserId = user.Id, RunningLow = redemption.RecoveryCodesRunningLow },
                cancellationToken);

            await trustedDevices.RevokeAllAsync(user.Id, "recovery-code-redeemed", now, cancellationToken);
        }

        // Only after a live second factor, or a device family could renew itself forever.
        var issued = redemption.UsedRecoveryCode
            ? null
            : await trustedDevices.IssueAsync(user, request, now, cancellationToken);

        logger.LogInformation("Sign-in completed for user {UserId} with a second factor.", user.Id);

        // The first factor comes off the challenge, since a magic-link challenge proved no password.
        var methods = SecondFactorMethods(redemption.AuthenticationMethods, redemption.UsedRecoveryCode);

        var result = await IssueAsync(
            user,
            familyId: null,
            familyStartedAt: null,
            methods,
            redemption.RecoveryCodesRunningLow,
            twoFactorSource: redemption.UsedRecoveryCode ? TwoFactorSource.Recovery : TwoFactorSource.Otp,
            secondFactorAt: now,
            trustedDevice: issued,
            newSignIn: true,
            client: ClientMetadata.Describe(request.UserAgent, request.IpAddress, options.Value.IpAddressStorage),
            now,
            cancellationToken);

        metrics.SignInCompleted(result.Outcome, methods);
        return result;
    }

    public async Task<SignInResult> VerifyMagicLinkAsync(MagicLinkSignInRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();
        var stored = await magicLinkTokens.FindByHashAsync(SecureTokens.HashToken(request.Token), cancellationToken);

        // Unknown, spent and expired are deliberately one answer to whoever holds the link.
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now)
        {
            logger.LogWarning("Magic-link sign-in refused: the token is unknown, already used or expired.");

            await events.PublishAsync(
                new SignInFailed { OccurredAt = now, UserId = stored?.UserId, Reason = SignInOutcome.InvalidMagicLink },
                cancellationToken);

            return Refused(SignInOutcome.InvalidMagicLink);
        }

        var user = await users.FindByIdAsync(stored.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Magic-link token {stored.Id} points at user {stored.UserId}, which does not exist.");

        // Spent before the challenge, so no live credential stays in a mailbox, and only by whoever
        // wins the conditional write, since the check above is a separate step.
        if (!await magicLinkTokens.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Magic-link sign-in refused for user {UserId}: the link was spent by another request.", stored.UserId);

            await events.PublishAsync(
                new SignInFailed { OccurredAt = now, UserId = stored.UserId, Reason = SignInOutcome.InvalidMagicLink },
                cancellationToken);

            return Refused(SignInOutcome.InvalidMagicLink);
        }

        await magicLinkTokens.InvalidateAllForUserAsync(stored.UserId, now, cancellationToken);

        // No device token here: a mailbox plus a cached factor is not two factors.
        if (await twoFactor.RequiresChallengeAsync(user.Id, cancellationToken))
        {
            var challenge = await twoFactor.IssueChallengeAsync(
                user.Id,
                now,
                cancellationToken,
                authenticationMethods: ToamaisutaaDefaults.MagicLinkMethod);

            logger.LogInformation("Magic link accepted for user {UserId}; a second factor is required.", user.Id);

            metrics.SignInCompleted(SignInOutcome.TwoFactorRequired, methods: null);

            return new SignInResult { Outcome = SignInOutcome.TwoFactorRequired, Challenge = challenge };
        }

        logger.LogInformation("Sign-in succeeded for user {UserId} with a magic link.", user.Id);

        string[] methods = [ToamaisutaaDefaults.MagicLinkMethod];

        var result = await IssueAsync(
            user,
            familyId: null,
            familyStartedAt: null,
            methods,
            recoveryCodesRunningLow: false,
            twoFactorSource: null,
            secondFactorAt: null,
            trustedDevice: null,
            newSignIn: true,
            client: ClientMetadata.Describe(request.UserAgent, request.IpAddress, options.Value.IpAddressStorage),
            now,
            cancellationToken);

        metrics.SignInCompleted(result.Outcome, methods);
        return result;
    }

    public async Task<StepUpChallengeResult> BeginStepUpAsync(StepUpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();
        var guard = await GuardStepUpAsync(request.UserId, request.SessionId, now, cancellationToken);

        if (guard.Outcome != SignInOutcome.Succeeded)
            return new StepUpChallengeResult { Outcome = guard.Outcome };

        var challenge = await twoFactor.IssueChallengeAsync(
            request.UserId,
            now,
            cancellationToken,
            TwoFactorChallengePurpose.StepUp,
            request.SessionId);

        logger.LogInformation("Step-up challenge issued for user {UserId} on session {SessionId}.", request.UserId, request.SessionId);

        return new StepUpChallengeResult { Outcome = SignInOutcome.Succeeded, Challenge = challenge };
    }

    public async Task<StepUpResult> CompleteStepUpAsync(StepUpVerificationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();
        var guard = await GuardStepUpAsync(request.UserId, request.SessionId, now, cancellationToken);

        if (guard.Outcome != SignInOutcome.Succeeded)
            return new StepUpResult { Outcome = guard.Outcome };

        var live = guard.Live!;
        var credential = guard.Credential!;
        AttemptReservation? reservation = null;

        var redemption = await twoFactor.RedeemChallengeAsync(
            request.ChallengeToken,
            request.Code,
            now,
            cancellationToken,
            TwoFactorChallengePurpose.StepUp,
            request.SessionId,
            refuseAttempt: async _ =>
            {
                // Reserved before the code is checked. A stolen access token can lock the owner out
                // of step-up, which beats handing it an unthrottled six-digit oracle.
                reservation = await credentials.ReserveAttemptAsync(credential, options.Value, now, cancellationToken);
                credential = reservation.Value.Credential;
                return !reservation.Value.Allowed;
            });

        if (redemption.Outcome != SignInOutcome.Succeeded)
        {
            if (redemption.Outcome == SignInOutcome.InvalidTwoFactorCode && reservation is { } reserved)
                await ReportWrongCodeAsync(reserved, "Step-up", now, cancellationToken);
            else
                await GiveBackLostRaceAsync(redemption.Outcome, request.UserId, reservation, null, now, cancellationToken);

            await events.PublishAsync(
                new TwoFactorFailed { OccurredAt = now, UserId = request.UserId, Reason = redemption.Outcome },
                cancellationToken);

            return new StepUpResult { Outcome = redemption.Outcome };
        }

        // Only this reservation back, not the whole count, which also holds wrong passwords; clearing
        // it would let a session holder reset password guessing with every step-up.
        if (reservation is { } spent)
            await credentials.RefundAsync(spent, now, cancellationToken);

        // A recovery code means the authenticator is gone, wherever it was typed.
        if (redemption.UsedRecoveryCode)
        {
            await events.PublishAsync(
                new RecoveryCodeUsed { OccurredAt = now, UserId = request.UserId, RunningLow = redemption.RecoveryCodesRunningLow },
                cancellationToken);

            await trustedDevices.RevokeAllAsync(request.UserId, "recovery-code-redeemed", now, cancellationToken);
        }

        var user = await users.FindByIdAsync(request.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Step-up names user {request.UserId}, which does not exist.");

        var source = redemption.UsedRecoveryCode ? TwoFactorSource.Recovery : TwoFactorSource.Otp;
        var methods = StepUpMethods(live.AuthenticationMethods, redemption.UsedRecoveryCode);

        // The refresh row FIRST, then the token: the other order can hand out a token claiming
        // freshness the row contradicts at the next refresh.
        if (!await refreshTokens.UpdateSecondFactorAsync(request.SessionId, string.Join(' ', methods), source, now, cancellationToken))
        {
            logger.LogWarning(
                "Step-up refused for user {UserId}: session {SessionId} stopped being live between the guard and the update.",
                request.UserId,
                request.SessionId);

            return new StepUpResult { Outcome = SignInOutcome.SessionEnded };
        }

        var access = await accessTokens.IssueAsync(
            new AccessTokenRequest
            {
                User = user,
                Roles = await roles.GetRolesAsync(user, cancellationToken),
                VerifiedEmail = credential.EmailConfirmedAt is not null ? credential.Email : null,
                AuthenticationMethods = methods,
                TwoFactorEnrolmentRequired = await twoFactor.MustEnrolAsync(user.Id, cancellationToken),
                TwoFactorSource = source,
                SecondFactorAt = now,
                SessionId = request.SessionId,
            },
            cancellationToken);

        logger.LogInformation(
            "Step-up completed for user {UserId} on session {SessionId} with {Source}.",
            request.UserId,
            request.SessionId,
            source);

        return new StepUpResult
        {
            Outcome = SignInOutcome.Succeeded,
            AccessToken = access.Value,
            ExpiresIn = (int)Math.Max(0, (access.ExpiresAt - now).TotalSeconds),
            RecoveryCodesRunningLow = redemption.RecoveryCodesRunningLow,
        };
    }

    private async Task<StepUpGuard> GuardStepUpAsync(
        Guid userId,
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // The session, not just the user: a signed-out family's access token is still valid for a
        // while, and elevating it would resurrect a session the user ended.
        var live = await refreshTokens.FindLiveByFamilyAsync(sessionId, cancellationToken);

        if (live is null || live.UserId != userId)
        {
            logger.LogInformation("Step-up refused for user {UserId}: session {SessionId} is no longer live.", userId, sessionId);
            return StepUpGuard.Failed(SignInOutcome.SessionEnded);
        }

        if (!await twoFactor.RequiresChallengeAsync(userId, cancellationToken))
            return StepUpGuard.Failed(SignInOutcome.TwoFactorNotEnrolled);

        // Fails closed: with no credential there is nothing to count lockout against, and the code
        // endpoint would be unthrottled.
        var credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            logger.LogWarning(
                "Step-up refused for user {UserId}: the session is locally issued but has no password credential, "
                + "so lockout cannot be enforced against it.",
                userId);

            return StepUpGuard.Failed(SignInOutcome.NotALocalSession);
        }

        if (LockoutPolicy.IsLockedOut(credential, now))
        {
            logger.LogWarning(
                "Step-up refused for user {UserId}: locked out until {LockedOutUntil}.",
                userId,
                credential.LockedOutUntil);

            return StepUpGuard.Failed(SignInOutcome.LockedOut);
        }

        return new StepUpGuard { Outcome = SignInOutcome.Succeeded, Live = live, Credential = credential };
    }

    /// <summary>
    /// Empty <paramref name="firstFactor"/> reads as <c>pwd</c> because older challenge rows were all
    /// password sign-ins.
    /// </summary>
    private static string[] SecondFactorMethods(string? firstFactor, bool usedRecoveryCode)
    {
        string[] proved = string.IsNullOrEmpty(firstFactor)
            ? ["pwd"]
            : firstFactor.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return usedRecoveryCode
            ? [.. proved, ToamaisutaaDefaults.MultiFactorMethod]
            : [.. proved, "otp", ToamaisutaaDefaults.MultiFactorMethod];
    }

    /// <summary>
    /// Monotonic, so no policy that passed before a step-up can fail after one. A recovery code adds
    /// only <c>mfa</c>, since RFC 8176 has no recovery value; <c>toa_2fa_source</c> says which it was.
    /// </summary>
    private static IReadOnlyList<string> StepUpMethods(string existing, bool usedRecoveryCode)
    {
        var methods = existing.Length == 0
            ? new List<string> { "pwd" }
            : [.. existing.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        Add(ToamaisutaaDefaults.MultiFactorMethod);

        if (!usedRecoveryCode)
            Add("otp");

        return methods;

        void Add(string method)
        {
            if (!methods.Contains(method, StringComparer.Ordinal))
                methods.Add(method);
        }
    }

    private readonly record struct StepUpGuard
    {
        internal SignInOutcome Outcome { get; init; }

        internal ToamaisutaaRefreshToken? Live { get; init; }

        internal ToamaisutaaPasswordCredential? Credential { get; init; }

        internal static StepUpGuard Failed(SignInOutcome outcome) => new() { Outcome = outcome };
    }

    public async Task<SignInResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var now = timeProvider.GetUtcNow();
        var stored = await refreshTokens.FindByHashAsync(SecureTokens.HashToken(refreshToken), cancellationToken);

        if (stored is null)
            return Failed(SignInOutcome.InvalidRefreshToken);

        if (stored.RotatedAt is not null)
            return await RefuseReusedAsync(stored, now, cancellationToken);

        if (stored.RevokedAt is not null)
            return Failed(SignInOutcome.RefreshTokenRevoked);

        if (stored.ExpiresAt <= now)
            return Failed(SignInOutcome.RefreshTokenExpired);

        // Rotation alone would keep a session alive forever; the family's age ends it.
        if (now - stored.FamilyStartedAt >= options.Value.RefreshTokenAbsoluteLifetime)
        {
            logger.LogInformation(
                "Refresh refused for user {UserId}: family {FamilyId} reached its absolute lifetime.",
                stored.UserId,
                stored.FamilyId);

            await RevokeFamilyAsync(stored, "absolute-lifetime-reached", now, cancellationToken);
            return Failed(SignInOutcome.RefreshTokenExpired);
        }

        var user = await users.FindByIdAsync(stored.UserId, cancellationToken)
            ?? throw new InvalidOperationException($"Refresh token {stored.Id} points at user {stored.UserId}, which does not exist.");

        // Credential changes revoke families outright, so a stale stamp on a live family means those
        // writes disagree, which is exactly when to refuse.
        if (!string.Equals(stored.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Refresh refused for user {UserId}: family {FamilyId} was minted before a credential changed.",
                stored.UserId,
                stored.FamilyId);

            await RevokeFamilyAsync(stored, "security-stamp-changed", now, cancellationToken);
            return Failed(SignInOutcome.SecurityStampChanged);
        }

        // The conditional write decides: the loser presented a token another request is exchanging,
        // which is reuse.
        if (!await refreshTokens.MarkRotatedAsync(stored.Id, now, cancellationToken))
        {
            // Losing to a sign-out or revocation is not reuse, and must not cost every trusted device.
            if (await refreshTokens.FindByHashAsync(stored.TokenHash, cancellationToken) is { RotatedAt: null, RevokedAt: not null })
                return Failed(SignInOutcome.RefreshTokenRevoked);

            return await RefuseReusedAsync(stored, now, cancellationToken);
        }

        var issued = await IssueAsync(
            user,
            stored.FamilyId,
            stored.FamilyStartedAt,
            stored.AuthenticationMethods.Length == 0 ? ["pwd"] : stored.AuthenticationMethods.Split(' '),
            recoveryCodesRunningLow: false,

            // Carried, never recomputed, or step-up policies start failing one access-token lifetime
            // after a good two-factor sign-in.
            twoFactorSource: stored.TwoFactorSource,
            secondFactorAt: stored.SecondFactorAt,
            trustedDevice: null,
            newSignIn: false,

            // Carried: refresh is made by background timers, which would otherwise redescribe the
            // session as whatever last renewed it.
            client: new ClientMetadata.SessionClient(stored.UserAgent, stored.IpAddress),
            now,
            cancellationToken);

        // Re-read after the insert: a revocation landing between rotation and insert missed the new
        // token, so either this sees the revocation or the revocation saw the token.
        if (issued.Succeeded
            && await refreshTokens.FindByHashAsync(stored.TokenHash, cancellationToken) is { RevokedAt: not null } revoked)
        {
            logger.LogWarning(
                "Refresh refused for user {UserId}: family {FamilyId} was revoked while it was being rotated.",
                stored.UserId,
                stored.FamilyId);

            await RevokeFamilyAsync(stored, revoked.RevokedReason ?? "revoked-during-refresh", now, cancellationToken);
            return Failed(SignInOutcome.RefreshTokenRevoked);
        }

        return issued;
    }

    /// <summary>
    /// Two parties hold the chain and there is no way to tell which is the owner, so neither keeps it.
    /// </summary>
    private async Task<SignInResult> RefuseReusedAsync(ToamaisutaaRefreshToken stored, DateTimeOffset now, CancellationToken cancellationToken)
    {
        logger.LogWarning(
            "Refresh token reuse detected for user {UserId}. Token {TokenId} was already rotated; "
            + "revoking the whole family {FamilyId}. Treat this as a possible stolen token.",
            stored.UserId,
            stored.Id,
            stored.FamilyId);

        metrics.RefreshTokenReuseDetected();

        await events.PublishAsync(
            new RefreshTokenReuseDetected { OccurredAt = now, UserId = stored.UserId, SessionId = stored.FamilyId },
            cancellationToken);

        await RevokeFamilyAsync(stored, "refresh-token-reuse", now, cancellationToken);

        // Explicit, because bumping the stamp would also revoke the user's other legitimate sessions.
        await trustedDevices.RevokeAllAsync(stored.UserId, "refresh-token-reuse", now, cancellationToken);

        return Failed(SignInOutcome.RefreshTokenReused);
    }

    public async Task SignOutAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var stored = await refreshTokens.FindByHashAsync(SecureTokens.HashToken(refreshToken), cancellationToken);
        if (stored is null)
            return;

        await RevokeFamilyAsync(stored, "signed-out", timeProvider.GetUtcNow(), cancellationToken);
        logger.LogInformation("Signed out user {UserId}; revoked refresh family {FamilyId}.", stored.UserId, stored.FamilyId);
    }

    private async Task RevokeFamilyAsync(
        ToamaisutaaRefreshToken stored,
        string reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await refreshTokens.RevokeFamilyAsync(stored.FamilyId, reason, now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked
            {
                OccurredAt = now,
                UserId = stored.UserId,
                SessionId = stored.FamilyId,
                Reason = reason,
            },
            cancellationToken);
    }

    private async Task<SignInResult> IssueAsync(
        ToamaisutaaUser user,
        Guid? familyId,
        DateTimeOffset? familyStartedAt,
        IReadOnlyList<string> methods,
        bool recoveryCodesRunningLow,
        string? twoFactorSource,
        DateTimeOffset? secondFactorAt,
        TrustedDeviceToken? trustedDevice,
        bool newSignIn,
        ClientMetadata.SessionClient client,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var issued = await sessions.IssueAsync(
            new LocalSessionRequest
            {
                User = user,
                FamilyId = familyId,
                FamilyStartedAt = familyStartedAt,
                Methods = methods,
                TwoFactorSource = twoFactorSource,
                SecondFactorAt = secondFactorAt,
                NewSignIn = newSignIn,
                Client = client,
                Now = now,
            },
            cancellationToken);

        return new SignInResult
        {
            Outcome = SignInOutcome.Succeeded,
            RecoveryCodesRunningLow = recoveryCodesRunningLow,
            TrustedDevice = trustedDevice,
            Tokens = issued.Tokens,
        };
    }

    private static SignInResult Failed(SignInOutcome outcome) => new() { Outcome = outcome };

    /// <summary>
    /// Refresh uses <see cref="Failed"/> instead, or the sign-in attempt rate would rise with session
    /// length rather than traffic.
    /// </summary>
    private SignInResult Refused(SignInOutcome outcome)
    {
        metrics.SignInCompleted(outcome, methods: null);
        return Failed(outcome);
    }

    private void VerifyDummy(string password)
    {
        var started = Stopwatch.GetTimestamp();
        dummy.Verify(password);
        metrics.PasswordVerified(started, result: null);
    }

    /// <summary>
    /// A right code that lost a race is not a wrong guess, so its reservation is given back, or a
    /// double-click on Verify leaves a failure behind.
    /// </summary>
    private async Task GiveBackLostRaceAsync(
        SignInOutcome outcome,
        Guid? userId,
        AttemptReservation? reservation,
        EnrolmentReservation? enrolmentReservation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (outcome != SignInOutcome.ChallengeAlreadyUsed)
            return;

        if (reservation is { Allowed: true } reserved)
            await credentials.TryRefundAsync(reserved, now, cancellationToken);
        else if (enrolmentReservation is { } enrolmentReserved && userId is { } id)
            await twoFactor.TryRefundEnrolmentAttemptAsync(id, enrolmentReserved, now, cancellationToken);
    }

    private async Task<SignInResult> LockedWhileVerifyingAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        logger.LogWarning("Sign-in refused for user {UserId}: the password was right, but other attempts locked the account while it was being checked.", userId);

        await events.PublishAsync(
            new SignInFailed { OccurredAt = now, UserId = userId, Reason = SignInOutcome.LockedOut },
            cancellationToken);

        return Refused(SignInOutcome.LockedOut);
    }

    /// <summary>A wrong second factor, already counted by its reservation exactly as a wrong password
    /// is, wherever it was typed. What is left is to say so, and to say once if it set the lock.</summary>
    private async Task ReportWrongCodeAsync(
        AttemptReservation reservation,
        string ceremony,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var credential = reservation.Credential;

        logger.LogWarning(
            "{Ceremony} refused for user {UserId}: wrong code. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
            ceremony,
            credential.UserId,
            credential.FailedAttemptCount,
            credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);

        if (reservation.LockedByThisAttempt && credential.LockedOutUntil is { } lockedOutUntil)
            await ReportLockedOutAsync(credential.UserId, lockedOutUntil, now, cancellationToken);
    }

    private async Task ReportLockedOutAsync(Guid userId, DateTimeOffset lockedOutUntil, DateTimeOffset now, CancellationToken cancellationToken)
    {
        logger.LogWarning("User {UserId} is locked out until {LockedOutUntil}.", userId, lockedOutUntil);
        metrics.LockedOut();

        await events.PublishAsync(
            new AccountLockedOut { OccurredAt = now, UserId = userId, LockedOutUntil = lockedOutUntil },
            cancellationToken);
    }
}
