namespace Toamaisutaa.Abstractions;

/// <summary>
/// Wrong passwords at sign-in, counted per account and per source, so whoever guesses locks out the
/// source they guess from rather than the account's owner.
/// </summary>
/// <remarks>
/// One row per (account, source). <see cref="Source"/> is a hash, never an address: of the caller's
/// address, of a trusted device's family when the caller presents one, or
/// <see cref="AccountWideSource"/> for the ceiling every source counts towards.
/// </remarks>
public class ToamaisutaaSignInThrottle
{
    /// <summary>The row every wrong password counts towards, whatever its source.</summary>
    public const string AccountWideSource = "*";

    public Guid UserId { get; set; }

    public string Source { get; set; } = default!;

    public int FailedAttemptCount { get; set; }

    public DateTimeOffset? FirstFailedAttemptAt { get; set; }

    public DateTimeOffset? LockedOutUntil { get; set; }
}
