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
