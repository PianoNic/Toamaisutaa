using System.Net;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Counts wrong passwords at sign-in per account and source, so guessing locks out the guesser's
/// source rather than the owner. The account-wide ceiling is one more source, the same rule with a
/// higher threshold.
/// </summary>
internal sealed class SignInThrottle(ISignInThrottleStore store, IOptions<ToamaisutaaLocalLoginOptions> options)
{
    // Every attempt is a read and a conditional write, and a flood moves the count under each other.
    private const int MaxAttempts = 50;

    /// <summary>
    /// A hash, so the table holds no address. IPv6 by its /64, which is what one subscriber is handed;
    /// counting single addresses there would give each one a fresh budget.
    /// </summary>
    internal static string ForAddress(string? ipAddress)
    {
        var key = IPAddress.TryParse(ipAddress, out var address)
            ? address.IsIPv4MappedToIPv6
                ? address.MapToIPv4().ToString()
                : address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? new IPAddress([.. address.GetAddressBytes()[..8], .. new byte[8]]).ToString() + "/64"
                    : address.ToString()
            : "unknown";

        return SecureTokens.HashToken("ip:" + key);
    }

    internal static string ForDevice(Guid familyId) => SecureTokens.HashToken("device:" + familyId.ToString("N"));

    /// <summary>
    /// Counts an attempt before its password is checked, so parallel guesses cannot each find the
    /// source open. Refused when a lock stands, or when a flood keeps moving the count.
    /// </summary>
    internal async Task<ThrottleReservation> ReserveAsync(
        Guid userId,
        string source,
        int threshold,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var settings = options.Value;

        if (!settings.LockoutEnabled)
            return ThrottleReservation.NotCounted;

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            var current = LockoutState.Of(await store.FindAsync(userId, source, cancellationToken));

            if (LockoutPolicy.IsLockedOut(current, now))
                return new ThrottleReservation(source, threshold, Allowed: false, Counted: false, current, current, LockedByThisAttempt: false);

            var next = LockoutPolicy.RegisterFailure(current, settings, now, threshold);

            if (await TryMoveAsync(userId, source, current, next, cancellationToken))
                return new ThrottleReservation(source, threshold, Allowed: true, Counted: true, current, next, LockoutPolicy.IsLockedOut(next, now));
        }

        return new ThrottleReservation(source, threshold, Allowed: false, Counted: false, LockoutState.Clear, LockoutState.Clear, LockedByThisAttempt: false);
    }

    /// <summary>Gives back only this attempt, so a right password cannot wipe out what others guessed.</summary>
    internal async Task RefundAsync(Guid userId, ThrottleReservation reservation, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!reservation.Counted)
            return;

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            var state = LockoutState.Of(await store.FindAsync(userId, reservation.Source, cancellationToken));

            var refunded = LockoutPolicy.Refund(
                state,
                reservation.LockedByThisAttempt,
                reservation.Before,
                reservation.After,
                options.Value,
                now,
                reservation.Threshold);

            if (refunded is not { } next || await TryMoveAsync(userId, reservation.Source, state, next, cancellationToken))
                return;
        }
    }

    /// <summary>
    /// The source's whole count, after a right password from it. Typos before it should not still be
    /// held against the owner, and guesses from a shared address are bounded by the ceiling anyway.
    /// </summary>
    /// <returns>False, clearing nothing, when other attempts locked the source meanwhile.</returns>
    internal async Task<bool> TryClearAsync(Guid userId, ThrottleReservation reservation, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!reservation.Counted)
            return true;

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            var state = LockoutState.Of(await store.FindAsync(userId, reservation.Source, cancellationToken));

            if (LockedByOthers(state, reservation, now))
                return false;

            if (state == LockoutState.Clear || await TryMoveAsync(userId, reservation.Source, state, LockoutState.Clear, cancellationToken))
                return true;
        }

        return false;
    }

    /// <summary>Gives back a right password's reservation, as <see cref="RefundAsync"/> does.</summary>
    /// <returns>False, giving nothing back, when other attempts locked the source meanwhile.</returns>
    internal async Task<bool> TryRefundRightAsync(Guid userId, ThrottleReservation reservation, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!reservation.Counted)
            return true;

        if (LockedByOthers(LockoutState.Of(await store.FindAsync(userId, reservation.Source, cancellationToken)), reservation, now))
            return false;

        await RefundAsync(userId, reservation, now, cancellationToken);
        return true;
    }

    /// <summary>
    /// One right guess in a parallel wave must not unlock what the rest of the wave just locked. A lock
    /// this attempt's own reservation set is the ordinary last try, and may still sign in.
    /// </summary>
    private static bool LockedByOthers(LockoutState state, ThrottleReservation reservation, DateTimeOffset now) =>
        LockoutPolicy.IsLockedOut(state, now) && !(reservation.LockedByThisAttempt && state.Matches(reservation.After));

    private Task<bool> TryMoveAsync(Guid userId, string source, LockoutState from, LockoutState to, CancellationToken cancellationToken) =>
        store.UpdateFailedAttemptsAsync(
            userId,
            source,
            from.FailedAttemptCount,
            from.FirstFailedAttemptAt,
            from.LockedOutUntil,
            to.FailedAttemptCount,
            to.FirstFailedAttemptAt,
            to.LockedOutUntil,
            cancellationToken);
}

internal readonly record struct ThrottleReservation(
    string Source,
    int Threshold,
    bool Allowed,
    bool Counted,
    LockoutState Before,
    LockoutState After,
    bool LockedByThisAttempt)
{
    internal static ThrottleReservation NotCounted => new(string.Empty, 0, Allowed: true, Counted: false, LockoutState.Clear, LockoutState.Clear, false);
}
