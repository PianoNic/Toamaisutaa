using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The change is a function of the row, reapplied to a fresh read on conflict, so a failure counted
/// on top of another request's failure is two, not one written twice.
/// </summary>
internal static class CredentialWrites
{
    // A burst of n requests is about 2n writes to one row (reserve, then refund or clear), so a low
    // limit answers 500 to the request with the right code.
    private const int MaxAttempts = 50;

    /// <returns>The credential as written, a different instance after a retry.</returns>
    internal static async Task<ToamaisutaaPasswordCredential> UpdateAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        Action<ToamaisutaaPasswordCredential> change,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            change(credential);

            try
            {
                await store.UpdateAsync(credential, cancellationToken);
                return credential;
            }
            catch (CredentialConcurrencyException) when (attempt < MaxAttempts)
            {
                credential = await store.FindByUserIdAsync(credential.UserId, cancellationToken)
                    ?? throw new InvalidOperationException($"The credential for user {credential.UserId} was deleted while it was being updated.");
            }
        }
    }

    /// <summary>
    /// Counts an attempt before it is checked, so parallel guesses cannot all see the account open;
    /// no more than <c>MaxFailedAttempts</c> guesses are checked in a window however many arrive.
    /// </summary>
    internal static async Task<AttemptReservation> ReserveAttemptAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var allowed = false;
        var before = LockoutState.Clear;
        var after = LockoutState.Clear;

        credential = await store.UpdateAsync(
            credential,
            current =>
            {
                before = LockoutState.Of(current);
                after = before;
                allowed = !LockoutPolicy.IsLockedOut(before, now);

                if (!allowed)
                    return;

                LockoutPolicy.RegisterFailure(current, options, now);
                current.UpdatedAt = now;
                after = LockoutState.Of(current);
            },
            cancellationToken);

        return new AttemptReservation(credential, allowed, before, after, LockoutPolicy.IsLockedOut(after, now) && allowed);
    }

    /// <summary>
    /// Gives back only this reservation: clearing the whole count for a password that still owes a
    /// second factor would let whoever holds the password reset the count every few wrong codes.
    /// </summary>
    internal static Task<ToamaisutaaPasswordCredential> RefundAsync(
        this IPasswordCredentialStore store,
        AttemptReservation reservation,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        store.UpdateAsync(
            reservation.Credential,
            current =>
            {
                var refunded = LockoutPolicy.Refund(
                    LockoutState.Of(current),
                    reservation.LockedByThisAttempt,
                    reservation.Before,
                    reservation.After,
                    now);

                if (refunded is { } next)
                {
                    next.ApplyTo(current);
                    current.UpdatedAt = now;
                }
            },
            cancellationToken);

    /// <summary>
    /// For an attempt that lost a race the refund is a courtesy: one that cannot land leaves a failure
    /// counted, which is no reason to answer 500.
    /// </summary>
    internal static async Task TryRefundAsync(
        this IPasswordCredentialStore store,
        AttemptReservation reservation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        try
        {
            await store.RefundAsync(reservation, now, cancellationToken);
        }
        catch (CredentialConcurrencyException)
        {
        }
    }

    /// <summary>
    /// Counted against the lockout like a sign-in, or a stolen access token gets an unthrottled way to
    /// guess the password.
    /// </summary>
    /// <returns>Null when the password is right, otherwise what to tell the caller.</returns>
    internal static async Task<string?> CheckCurrentPasswordAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        string currentPassword,
        IPasswordHasher hasher,
        AuthenticationEventPublisher events,
        ToamaisutaaLocalLoginOptions options,
        ILogger logger,
        string action,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var reservation = await store.ReserveAttemptAsync(credential, options, now, cancellationToken);
        credential = reservation.Credential;

        if (!reservation.Allowed)
        {
            logger.LogWarning(
                "{Action} refused for user {UserId}: locked out until {LockedOutUntil}.",
                action,
                credential.UserId,
                credential.LockedOutUntil);

            return "Too many wrong passwords. Try again later.";
        }

        if (hasher.Verify(currentPassword, credential.PasswordHash) != PasswordVerificationResult.Failed)
        {
            // Refund only this reservation: a correct current password is not a sign-in and must not
            // clear what anyone else has guessed.
            await store.RefundAsync(reservation, now, cancellationToken);
            return null;
        }

        logger.LogWarning(
            "{Action} refused for user {UserId}: the current password is wrong. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
            action,
            credential.UserId,
            credential.FailedAttemptCount,
            credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);

        if (reservation.LockedByThisAttempt && credential.LockedOutUntil is { } lockedOutUntil)
        {
            await events.PublishAsync(
                new AccountLockedOut { OccurredAt = now, UserId = credential.UserId, LockedOutUntil = lockedOutUntil },
                cancellationToken);
        }

        return "Your current password is not correct.";
    }

    /// <summary>
    /// Sign-in accepts a user name or an email, so a value must not appear in either column of another
    /// account; the unique indexes only cover each column against itself.
    /// </summary>
    internal static async Task CreateCheckedAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        CancellationToken cancellationToken)
    {
        await ThrowIfTakenAsync(store, credential.UserId, credential.NormalizedUserName, cancellationToken);
        await ThrowIfTakenAsync(store, credential.UserId, credential.NormalizedEmail, cancellationToken);

        await store.CreateAsync(credential, cancellationToken);
    }

    internal static async Task<bool> IsTakenByAnotherAsync(
        this IPasswordCredentialStore store,
        Guid userId,
        string normalizedIdentifier,
        CancellationToken cancellationToken) =>
        await store.FindByIdentifierAsync(normalizedIdentifier, cancellationToken) is { } holder && holder.UserId != userId;

    private static async Task ThrowIfTakenAsync(
        IPasswordCredentialStore store,
        Guid userId,
        string? normalizedIdentifier,
        CancellationToken cancellationToken)
    {
        if (normalizedIdentifier is not null && await store.IsTakenByAnotherAsync(userId, normalizedIdentifier, cancellationToken))
            throw new PasswordIdentifierConflictException();
    }

    /// <summary>
    /// For accounts with no password credential to count on; without it the only limit on guessing
    /// their code is the per-address rate limiter. Reserved before the check, like the credential one.
    /// </summary>
    internal static async Task<EnrolmentReservation> ReserveAttemptAsync(
        this ITwoFactorStore store,
        Guid userId,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            // No enrolment means no secret, so the code fails on its own.
            if (await store.FindAsync(userId, cancellationToken) is not { } enrolment)
                return EnrolmentReservation.Uncounted(allowed: true);

            var current = LockoutState.Of(enrolment);

            if (LockoutPolicy.IsLockedOut(current, now))
                return EnrolmentReservation.Uncounted(allowed: false);

            var next = LockoutPolicy.RegisterFailure(current, options, now);

            if (await TryMoveCountAsync(store, userId, current, next, cancellationToken))
            {
                return new EnrolmentReservation(
                    Allowed: true,
                    LockedUntil: LockoutPolicy.IsLockedOut(next, now) ? next.LockedOutUntil : null,
                    Before: current,
                    After: next,
                    Counted: true);
            }
        }

        // Refused rather than checked uncounted when a flood keeps moving the count.
        return EnrolmentReservation.Uncounted(allowed: false);
    }

    internal static async Task TryRefundAttemptAsync(
        this ITwoFactorStore store,
        Guid userId,
        EnrolmentReservation reservation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!reservation.Counted)
            return;

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            if (await store.FindAsync(userId, cancellationToken) is not { } enrolment)
                return;

            var state = LockoutState.Of(enrolment);

            if (LockoutPolicy.Refund(state, reservation.LockedUntil is not null, reservation.Before, reservation.After, now) is not { } next)
                return;

            if (await TryMoveCountAsync(store, userId, state, next, cancellationToken))
                return;
        }
    }

    /// <summary>
    /// Retried because a missed write leaves the person signed in one typo from a lockout.
    /// </summary>
    internal static async Task RegisterSuccessAsync(this ITwoFactorStore store, Guid userId, CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            if (await store.FindAsync(userId, cancellationToken) is not { } enrolment || LockoutState.Of(enrolment) == LockoutState.Clear)
                return;

            if (await TryMoveCountAsync(store, userId, LockoutState.Of(enrolment), LockoutState.Clear, cancellationToken))
                return;
        }
    }

    /// <summary>Moves an enrolment's count, but only if it still reads <paramref name="from"/>, so a
    /// parallel attempt's write is lost to a retry rather than overwritten.</summary>
    private static Task<bool> TryMoveCountAsync(
        ITwoFactorStore store,
        Guid userId,
        LockoutState from,
        LockoutState to,
        CancellationToken cancellationToken) =>
        store.UpdateFailedAttemptsAsync(
            userId,
            from.FailedAttemptCount,
            from.FirstFailedAttemptAt,
            from.LockedOutUntil,
            to.FailedAttemptCount,
            to.FirstFailedAttemptAt,
            to.LockedOutUntil,
            cancellationToken);

    /// <summary>
    /// Refuses when a lock set by other attempts now stands, so one right guess in a parallel wave
    /// cannot unlock the account the rest of the wave just locked.
    /// </summary>
    /// <returns>False when the sign-in has to be refused as locked out.</returns>
    internal static async Task<bool> TryRegisterSuccessAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        AttemptReservation reservation,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        Rehash? rehash = null)
    {
        var refused = false;

        await store.UpdateAsync(
            credential,
            current =>
            {
                var state = LockoutState.Of(current);

                // A lock this attempt's own reservation set is the ordinary last try and may sign in.
                refused = LockoutPolicy.IsLockedOut(state, now)
                    && !(reservation.LockedByThisAttempt && state == reservation.After);

                if (refused)
                    return;

                rehash?.ApplyTo(current);
                LockoutPolicy.RegisterSuccess(current);
                current.UpdatedAt = now;
            },
            cancellationToken);

        return !refused;
    }

    internal static Task<ToamaisutaaPasswordCredential> RegisterSuccessAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        store.UpdateAsync(
            credential,
            current =>
            {
                LockoutPolicy.RegisterSuccess(current);
                current.UpdatedAt = now;
            },
            cancellationToken);
}

internal readonly record struct EnrolmentReservation(
    bool Allowed,
    DateTimeOffset? LockedUntil,
    LockoutState Before,
    LockoutState After,
    bool Counted)
{
    internal static EnrolmentReservation Uncounted(bool allowed) =>
        new(allowed, null, LockoutState.Clear, LockoutState.Clear, Counted: false);
}

internal readonly record struct Rehash(string VerifiedHash, string NewHash)
{
    /// <summary>Only over the hash that was verified, so a reset that landed in between is not undone.</summary>
    internal void ApplyTo(ToamaisutaaPasswordCredential current)
    {
        if (current.PasswordHash == VerifiedHash)
            current.PasswordHash = NewHash;
    }
}

internal readonly record struct AttemptReservation(
    ToamaisutaaPasswordCredential Credential,
    bool Allowed,
    LockoutState Before,
    LockoutState After,
    bool LockedByThisAttempt);
