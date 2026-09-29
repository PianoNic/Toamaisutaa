using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Counting failures and deciding when to stop accepting attempts. Counted against the account, not
/// the caller's address, which is what makes it useful against guessing and useless against someone
/// simply trying to lock a known account out - see the rate limiter for the other half.
/// </summary>
/// <remarks>
/// The arithmetic is on <see cref="LockoutState"/> so the password credential and a two-factor
/// enrolment count by one rule: an account with no password keeps its count on the enrolment, and
/// the two must not drift into different thresholds.
/// </remarks>
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

        // Failures spread further apart than the window are not an attack, they are someone with a
        // bad memory. Start counting again rather than accumulating forever.
        var counted = state.FirstFailedAttemptAt is not { } first || now - first > options.LockoutWindow
            ? state with { FirstFailedAttemptAt = now, FailedAttemptCount = 1 }
            : state with { FailedAttemptCount = state.FailedAttemptCount + 1 };

        if (counted.FailedAttemptCount < options.MaxFailedAttempts)
            return counted;

        // Clear the counter with the lock, so the window starts fresh when the lock expires instead
        // of the next single failure re-locking the account immediately.
        return new LockoutState(0, null, now + options.LockoutDuration);
    }

    internal static void RegisterSuccess(ToamaisutaaPasswordCredential credential) =>
        LockoutState.Clear.ApplyTo(credential);
}

/// <summary>A failure count, when it started, and the lock it led to, if any.</summary>
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
