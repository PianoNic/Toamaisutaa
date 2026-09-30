using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Works on <see cref="LockoutState"/> so the password credential and a two-factor enrolment count by
/// one rule and cannot drift into different thresholds.
/// </summary>
internal static class LockoutPolicy
{
    internal static bool IsLockedOut(ToamaisutaaPasswordCredential credential, DateTimeOffset now) =>
        IsLockedOut(LockoutState.Of(credential), now);

    internal static bool IsLockedOut(LockoutState state, DateTimeOffset now) =>
        state.LockedOutUntil is { } until && until > now;

    internal static void RegisterFailure(
        ToamaisutaaPasswordCredential credential,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now) =>
        RegisterFailure(LockoutState.Of(credential), options, now).ApplyTo(credential);

    internal static LockoutState RegisterFailure(LockoutState state, ToamaisutaaLocalLoginOptions options, DateTimeOffset now)
    {
        if (!options.LockoutEnabled)
            return state;

        var counted = state.FirstFailedAttemptAt is not { } first || now - first > options.LockoutWindow
            ? state with { FirstFailedAttemptAt = now, FailedAttemptCount = 1 }
            : state with { FailedAttemptCount = state.FailedAttemptCount + 1 };

        if (counted.FailedAttemptCount < options.MaxFailedAttempts)
            return counted;

        // Cleared with the lock so the next single failure after it expires does not re-lock.
        return new LockoutState(0, null, now + options.LockoutDuration);
    }

    internal static void RegisterSuccess(ToamaisutaaPasswordCredential credential) =>
        LockoutState.Clear.ApplyTo(credential);

    /// <summary>
    /// The count after giving back one reservation whose attempt was right, or null when there is
    /// nothing to give back. Only this attempt's share comes off: the lock it set, if that still
    /// stands untouched, undone to what it replaced; otherwise one failure off an unlocked count.
    /// </summary>
    internal static LockoutState? Refund(
        LockoutState state,
        bool lockedByThisAttempt,
        LockoutState before,
        LockoutState after,
        DateTimeOffset now)
    {
        if (lockedByThisAttempt && state == after)
            return before;

        if (!IsLockedOut(state, now) && state.FailedAttemptCount > 0)
            return state with { FailedAttemptCount = state.FailedAttemptCount - 1 };

        return null;
    }
}

internal readonly record struct LockoutState(int FailedAttemptCount, DateTimeOffset? FirstFailedAttemptAt, DateTimeOffset? LockedOutUntil)
{
    internal static LockoutState Clear => new(0, null, null);

    internal static LockoutState Of(ToamaisutaaPasswordCredential credential) =>
        new(credential.FailedAttemptCount, credential.FirstFailedAttemptAt, credential.LockedOutUntil);

    internal static LockoutState Of(ToamaisutaaUserTwoFactor enrolment) =>
        new(enrolment.FailedAttemptCount, enrolment.FirstFailedAttemptAt, enrolment.LockedOutUntil);

    internal void ApplyTo(ToamaisutaaPasswordCredential credential)
    {
        credential.FailedAttemptCount = FailedAttemptCount;
        credential.FirstFailedAttemptAt = FirstFailedAttemptAt;
        credential.LockedOutUntil = LockedOutUntil;
    }
}
