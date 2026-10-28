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

    /// <summary>On the account: escalates, since only someone holding the password or a session gets here.</summary>
    internal static LockoutState RegisterFailure(LockoutState state, ToamaisutaaLocalLoginOptions options, DateTimeOffset now) =>
        RegisterFailure(state, options, now, options.MaxFailedAttempts, escalate: true);

    internal static LockoutState RegisterFailure(
        LockoutState state,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        int threshold,
        bool escalate = false)
    {
        if (!options.LockoutEnabled)
            return state;

        var counted = state.FirstFailedAttemptAt is not { } first || now - first > options.LockoutWindow
            ? state with { FirstFailedAttemptAt = now, FailedAttemptCount = 1 }
            : state with { FailedAttemptCount = state.FailedAttemptCount + 1 };

        if (counted.FailedAttemptCount < threshold)
            return counted;

        // Cleared with the lock so the next single failure after it expires does not re-lock.
        var strikes = escalate ? counted.Strikes + 1 : 0;
        return new LockoutState(0, null, now + Duration(options, strikes), strikes);
    }

    /// <summary>Doubles per strike after the first, never past the cap.</summary>
    internal static TimeSpan Duration(ToamaisutaaLocalLoginOptions options, int strikes)
    {
        var cap = options.LockoutMaxDuration > options.LockoutDuration ? options.LockoutMaxDuration : options.LockoutDuration;
        var duration = options.LockoutDuration;

        for (var strike = 1; strike < strikes && duration < cap; strike++)
            duration += duration;

        return duration < cap ? duration : cap;
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
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now) =>
        Refund(state, lockedByThisAttempt, before, after, options, now, options.MaxFailedAttempts);

    internal static LockoutState? Refund(
        LockoutState state,
        bool lockedByThisAttempt,
        LockoutState before,
        LockoutState after,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        int threshold)
    {
        if (lockedByThisAttempt && state.Matches(after))
            return before;

        // Only into the window this attempt was counted in. A later window never counted it, and the
        // caller's clock is the one it reserved with, so comparing against now proves nothing.
        if (!IsLockedOut(state, now))
        {
            return state.FailedAttemptCount > 0 && LockoutState.SameInstant(state.FirstFailedAttemptAt, after.FirstFailedAttemptAt)
                ? state with { FailedAttemptCount = state.FailedAttemptCount - 1 }
                : null;
        }

        // Locked by another attempt's reservation. When that lock was set inside this attempt's
        // window, it was reached counting this right attempt, and without it the count stands one
        // short of the threshold, unlocked. A lock set after the window closed is someone else's.
        if (!lockedByThisAttempt
            && after.FirstFailedAttemptAt is { } windowStart
            && state.LockedOutUntil is { } until
            && until - Duration(options, state.Strikes) is var lockedAt
            && lockedAt >= windowStart
            && lockedAt - windowStart <= options.LockoutWindow)
        {
            return new LockoutState(threshold - 1, windowStart, null, Math.Max(0, state.Strikes - 1));
        }

        return null;
    }
}

internal readonly record struct LockoutState(
    int FailedAttemptCount,
    DateTimeOffset? FirstFailedAttemptAt,
    DateTimeOffset? LockedOutUntil,
    int Strikes = 0)
{
    internal static LockoutState Clear => new(0, null, null);

    /// <summary>
    /// Equal to the millisecond, which is what the stores keep: a state read back after a write never
    /// equals the one computed in memory at full precision.
    /// </summary>
    internal bool Matches(LockoutState other) =>
        FailedAttemptCount == other.FailedAttemptCount
        && SameInstant(FirstFailedAttemptAt, other.FirstFailedAttemptAt)
        && SameInstant(LockedOutUntil, other.LockedOutUntil)
        && Strikes == other.Strikes;

    internal static bool SameInstant(DateTimeOffset? left, DateTimeOffset? right) =>
        left?.ToUnixTimeMilliseconds() == right?.ToUnixTimeMilliseconds();

    internal static LockoutState Of(ToamaisutaaPasswordCredential credential) =>
        new(credential.FailedAttemptCount, credential.FirstFailedAttemptAt, credential.LockedOutUntil, credential.LockoutStrikes);

    internal static LockoutState Of(ToamaisutaaUserTwoFactor enrolment) =>
        new(enrolment.FailedAttemptCount, enrolment.FirstFailedAttemptAt, enrolment.LockedOutUntil, enrolment.LockoutStrikes);

    internal static LockoutState Of(ToamaisutaaSignInThrottle? throttle) =>
        throttle is null ? Clear : new(throttle.FailedAttemptCount, throttle.FirstFailedAttemptAt, throttle.LockedOutUntil);

    internal void ApplyTo(ToamaisutaaPasswordCredential credential)
    {
        credential.FailedAttemptCount = FailedAttemptCount;
        credential.FirstFailedAttemptAt = FirstFailedAttemptAt;
        credential.LockedOutUntil = LockedOutUntil;
        credential.LockoutStrikes = Strikes;
    }
}
