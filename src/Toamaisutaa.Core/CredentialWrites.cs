using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// A change to a credential, reapplied to a fresh read whenever another request wrote first.
/// </summary>
/// <remarks>
/// The change is a function of the row rather than a value, which is what makes the retry correct:
/// a failed attempt counted on top of somebody else's failed attempt is two, not one written twice.
/// </remarks>
internal static class CredentialWrites
{
    /// <summary>Enough for any real contention on one account. Past it, something is wrong and
    /// failing the request says so rather than looping.</summary>
    /// <remarks>
    /// Each attempt is now counted before it is checked and given back or cleared after, so a burst
    /// of n requests on one account is about 2n writes to one row, and a request can lose each of
    /// them in turn. Ten parallel second factors could exhaust a limit of ten and answer 500 to the
    /// one with the right code.
    /// </remarks>
    private const int MaxAttempts = 50;

    /// <returns>The credential as written, which is a different instance after a retry. Read what
    /// happened off this one, not the one passed in.</returns>
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
    /// Counts an attempt before it is checked - a password or a second factor - and says whether it
    /// may be checked at all.
    /// </summary>
    /// <remarks>
    /// Counting after the check left every guess already in flight free: the lock was read before
    /// verifying, so parallel requests each saw the account open, each was checked, and only then did
    /// the count catch up. Reserved first, with the same conditional write, no more than
    /// <c>MaxFailedAttempts</c> guesses are ever checked in a window, however many arrive at once.
    /// A guess that turns out right gives its reservation back by clearing the count once a sign-in
    /// has finished, or with <see cref="RefundAsync"/> when it has not.
    /// </remarks>
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
    /// Gives back one reservation whose attempt was right but did not finish anything - a password
    /// that still owes a second factor. Everything else counted stays: clearing the whole count there
    /// would let whoever holds the password sign in again every few wrong codes and start over.
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
    /// <see cref="RefundAsync"/> for an attempt that lost a race, where the refund is a courtesy. A
    /// double-click leaves every losing request writing to one row at once, and a refund that cannot
    /// land among them is one failure left counted - not a reason to answer 500.
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
    /// The current password a signed-in caller answers, counted against the account exactly as a
    /// wrong password at sign-in is. A stolen access token reaches every place that asks for one, and
    /// without the count each of them is an unthrottled way to guess the one thing the token lacks.
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
            // Right, so the attempt gives its reservation back - and only its own: a correct current
            // password is not a sign-in, and does not wipe out what anyone else has guessed.
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
    /// Creates a credential in the one namespace the sign-in box reads. It takes a user name or an
    /// email, so a value one account holds in either column must not appear in the other column of a
    /// different account: a user name equal to somebody's address sent their sign-ins to the wrong row.
    /// </summary>
    /// <remarks>
    /// The unique indexes cover each column only against itself, which is why this asks the store the
    /// same question sign-in does rather than trusting the insert to fail.
    /// </remarks>
    internal static async Task CreateCheckedAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        CancellationToken cancellationToken)
    {
        await ThrowIfTakenAsync(store, credential.UserId, credential.NormalizedUserName, cancellationToken);
        await ThrowIfTakenAsync(store, credential.UserId, credential.NormalizedEmail, cancellationToken);

        await store.CreateAsync(credential, cancellationToken);
    }

    /// <summary>Whether another account answers to <paramref name="normalizedIdentifier"/> in
    /// either column.</summary>
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
    /// Counts one wrong code against the enrolment of an account that has no password credential
    /// to count it on - passkey-only, or owned by an identity provider. Without it, the only limit
    /// on guessing that account's code was the per-address rate limiter.
    /// </summary>
    /// <remarks>Reserved before the code is checked, for the reason the credential version gives.</remarks>
    /// <returns>Whether the code may be checked, and when this attempt is the one that locked it, until when.</returns>
    internal static async Task<EnrolmentReservation> ReserveAttemptAsync(
        this ITwoFactorStore store,
        Guid userId,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            // Nothing to count on: the code is checked and fails on its own, since there is no secret.
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

        // The count kept moving under every try, which only a flood of attempts does. Refused rather
        // than checked uncounted.
        return EnrolmentReservation.Uncounted(allowed: false);
    }

    /// <summary>
    /// Gives back one reservation on an enrolment whose attempt was right but lost a race, the same
    /// as <see cref="TryRefundAsync"/> does on a credential: the lock it set, if it still stands
    /// untouched, undone to what it replaced; otherwise one failure taken off an unlocked count. A
    /// courtesy, so one that cannot land is left.
    /// </summary>
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

    /// <summary>Clears the enrolment's count once a code has been accepted.</summary>
    /// <remarks>
    /// Retried, because a count that moved in between is only more failures and the right code clears
    /// those too. One write that missed left the person signed in one typo from a lockout.
    /// </remarks>
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
    /// Clears the count for a right password, unless a lock that other attempts set while this one
    /// was being hashed now stands. Clearing it regardless let one right guess in a parallel wave
    /// sign in and unlock the account the rest of the wave had just locked.
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

                // A lock this attempt's own reservation set is the ordinary last try, and a right
                // password there signs in exactly as it would have one at a time.
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

    /// <summary>Clears the count once a sign-in or step-up has finished.</summary>
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

/// <summary>What reserving an attempt on an enrolment did: whether it may be checked, until when it
/// locked the enrolment if it did, and the count before and after, for giving it back.</summary>
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

/// <summary>A stored password rehashed under current parameters, waiting to be written.</summary>
internal readonly record struct Rehash(string VerifiedHash, string NewHash)
{
    /// <summary>Only over the hash that was verified. A reset that landed in between wrote a new
    /// password, and the rehash of the old one must not undo it.</summary>
    internal void ApplyTo(ToamaisutaaPasswordCredential current)
    {
        if (current.PasswordHash == VerifiedHash)
            current.PasswordHash = NewHash;
    }
}

/// <summary>What reserving an attempt did: the credential as written, whether the attempt may be
/// checked, the count before and after, and whether this reservation is the one that locked it.</summary>
internal readonly record struct AttemptReservation(
    ToamaisutaaPasswordCredential Credential,
    bool Allowed,
    LockoutState Before,
    LockoutState After,
    bool LockedByThisAttempt);
