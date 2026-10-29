using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>What proving an address does to the other accounts that hold it, wherever it is proven.</summary>
internal static class EmailAddressHolds
{
    /// <summary>
    /// A proven claim outranks an unproven hold, or anybody could register someone else's address first
    /// and lock the real owner out.
    /// </summary>
    internal static async Task ReleaseUnverifiedHoldAsync(
        this IPasswordCredentialStore credentials,
        string normalizedEmail,
        Guid claimant,
        DateTimeOffset now,
        AuthenticationEventPublisher events,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var holder = await credentials.FindByNormalizedEmailAsync(normalizedEmail, cancellationToken);
        if (holder is null || holder.UserId == claimant || holder.EmailConfirmedAt is not null)
            return;

        // Read now: the update below clears it on this same instance.
        var releasedEmail = holder.Email ?? normalizedEmail;

        await credentials.UpdateAsync(
            holder,
            current =>
            {
                if (current.EmailConfirmedAt is not null || current.NormalizedEmail != normalizedEmail)
                    return;

                current.Email = null;
                current.NormalizedEmail = null;
                current.UpdatedAt = now;
            },
            cancellationToken);

        logger.LogWarning(
            "Released the unverified email address held by user {HolderId}: user {ClaimantId} proved they own it.",
            holder.UserId,
            claimant);

        await events.PublishAsync(
            new EmailAddressReleased { OccurredAt = now, UserId = holder.UserId, Email = releasedEmail, ClaimedByUserId = claimant },
            cancellationToken);
    }
}
