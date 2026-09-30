using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

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
                ProfileNeedsUpdate = context.SyncMode != ProfileSyncMode.Never,
            };
        }

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
