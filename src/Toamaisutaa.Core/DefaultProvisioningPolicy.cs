using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Subject-only linking: a known (provider, subject) is the user it points at, and an unknown one
/// gets a new user. There is nothing to match an unknown subject against, so
/// <see cref="ProvisioningAction.LinkExisting"/> only happens when something upstream supplied a
/// candidate, which nothing does today.
/// </summary>
internal sealed class DefaultProvisioningPolicy : IProvisioningPolicy
{
    public ProvisioningDecision Decide(ProvisioningContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ExistingLogin is { } login)
        {
            var user = context.LinkedUser
                ?? throw new InvalidOperationException(
                    "ProvisioningContext.ExistingLogin was supplied without its LinkedUser, so there is nothing to decide about.");

            return new ProvisioningDecision
            {
                Action = ProvisioningAction.AlreadyLinked,
                UserId = user.Id,
                ExternalLoginId = login.Id,
                ProfileNeedsUpdate = NeedsUpdate(context.SyncMode, user, context.Profile),
            };
        }

        if (context.LinkCandidate is { } candidate)
        {
            return new ProvisioningDecision
            {
                Action = ProvisioningAction.LinkExisting,
                UserId = candidate.Id,
                // The candidate row predates this provider, so its profile came from somewhere
                // else. Anything but Never means the token that just arrived should win.
                ProfileNeedsUpdate = context.SyncMode != ProfileSyncMode.Never,
            };
        }

        // The insert writes the profile, so there is never a follow-up update to do.
        return new ProvisioningDecision { Action = ProvisioningAction.CreateNew };
    }

    private static bool NeedsUpdate(ProfileSyncMode mode, ToamaisutaaUser user, ExternalUserProfile profile) => mode switch
    {
        ProfileSyncMode.Never or ProfileSyncMode.FirstSignInOnly => false,
        ProfileSyncMode.OnChange => ProfileComparer.HasChanges(user, profile),
        ProfileSyncMode.EveryRequest => true,
        _ => false,
    };
}
