using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Counting failures and deciding when to stop accepting attempts. Counted against the account, not
/// the caller's address, which is what makes it useful against guessing and useless against someone
/// simply trying to lock a known account out - see the rate limiter for the other half.
/// </summary>
internal static class LockoutPolicy
{
    internal static bool IsLockedOut(ToamaisutaaPasswordCredential credential, DateTimeOffset now) =>
        credential.LockedOutUntil is { } until && until > now;

    internal static void RegisterFailure(
        ToamaisutaaPasswordCredential credential,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now)
    {
        if (!options.LockoutEnabled)
            return;

        // Failures spread further apart than the window are not an attack, they are someone with a
        // bad memory. Start counting again rather than accumulating forever.
        if (credential.FirstFailedAttemptAt is not { } first || now - first > options.LockoutWindow)
        {
            credential.FirstFailedAttemptAt = now;
            credential.FailedAttemptCount = 1;
        }
        else
        {
            credential.FailedAttemptCount++;
        }

        if (credential.FailedAttemptCount < options.MaxFailedAttempts)
            return;

        credential.LockedOutUntil = now + options.LockoutDuration;

        // Clear the counter with the lock, so the window starts fresh when the lock expires instead
        // of the next single failure re-locking the account immediately.
        credential.FailedAttemptCount = 0;
        credential.FirstFailedAttemptAt = null;
    }

    internal static void RegisterSuccess(ToamaisutaaPasswordCredential credential)
    {
        credential.FailedAttemptCount = 0;
        credential.FirstFailedAttemptAt = null;
        credential.LockedOutUntil = null;
    }
}
