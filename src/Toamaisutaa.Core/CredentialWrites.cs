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
    private const int MaxAttempts = 10;

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

    /// <summary>Counts one failed attempt - a wrong password or a wrong second factor.</summary>
    /// <returns>
    /// The credential as written, and whether this attempt is the one that locked it. A racing
    /// attempt that got there first owns the lock and its event; this one is refused all the same
    /// and counts for nothing further, so the lock is not stretched by the requests queued behind it.
    /// </returns>
    internal static async Task<(ToamaisutaaPasswordCredential Credential, bool LockedByThisAttempt)> RegisterFailureAsync(
        this IPasswordCredentialStore store,
        ToamaisutaaPasswordCredential credential,
        ToamaisutaaLocalLoginOptions options,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var lockedByThisAttempt = false;

        credential = await store.UpdateAsync(
            credential,
            current =>
            {
                lockedByThisAttempt = false;

                if (LockoutPolicy.IsLockedOut(current, now))
                    return;

                LockoutPolicy.RegisterFailure(current, options, now);
                current.UpdatedAt = now;
                lockedByThisAttempt = LockoutPolicy.IsLockedOut(current, now);
            },
            cancellationToken);

        return (credential, lockedByThisAttempt);
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
        if (LockoutPolicy.IsLockedOut(credential, now))
        {
            logger.LogWarning(
                "{Action} refused for user {UserId}: locked out until {LockedOutUntil}.",
                action,
                credential.UserId,
                credential.LockedOutUntil);

            return "Too many wrong passwords. Try again later.";
        }

        if (hasher.Verify(currentPassword, credential.PasswordHash) != PasswordVerificationResult.Failed)
            return null;

        (credential, var lockedByThisAttempt) = await store.RegisterFailureAsync(credential, options, now, cancellationToken);

        logger.LogWarning(
            "{Action} refused for user {UserId}: the current password is wrong. {FailedAttempts} failed attempt(s) in the current window{Locked}.",
            action,
            credential.UserId,
            credential.FailedAttemptCount,
            credential.LockedOutUntil is { } until ? $"; locked out until {until:O}" : string.Empty);

        if (lockedByThisAttempt && credential.LockedOutUntil is { } lockedOutUntil)
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
