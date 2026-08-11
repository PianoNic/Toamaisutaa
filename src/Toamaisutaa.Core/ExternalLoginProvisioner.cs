using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>Applies the provisioning decision to the stores.</summary>
internal sealed class ExternalLoginProvisioner(
    IClaimsProfileMapper mapper,
    IProvisioningPolicy policy,
    IUserStore userStore,
    IExternalLoginStore externalLoginStore,
    IOptions<ToamaisutaaProvisioningOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLoginOptions,
    TimeProvider timeProvider,
    ILogger<ExternalLoginProvisioner> logger) : IExternalLoginProvisioner
{
    public async Task<ToamaisutaaUser> ProvisionAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default)
    {
        // A token this package issued names a local user directly and has no external login behind
        // it. Left to the normal path, its subject would look like one nobody has ever seen and
        // every request would provision another duplicate user.
        if (TryGetLocallyIssuedUserId(principal, out var localUserId))
        {
            return await userStore.FindByIdAsync(localUserId, cancellationToken)
                ?? throw new InvalidOperationException(
                    $"A locally issued token names user {localUserId}, which no longer exists.");
        }

        var profile = mapper.Map(principal);

        try
        {
            return await RunAsync(profile, cancellationToken);
        }
        catch (ExternalLoginConflictException exception)
        {
            // Two first requests for the same never-seen subject raced and both decided to create.
            // The loser lands here; the winner's row now exists, so a second pass finds it and
            // takes the AlreadyLinked path. One retry is enough: the pair is unique, so the row
            // cannot disappear again.
            logger.LogDebug(
                exception,
                "Concurrent first sign-in for provider {ProviderKey}; re-reading the row the other request created.",
                options.Value.ProviderKey);

            return await RunAsync(profile, cancellationToken);
        }
    }

    /// <summary>
    /// Decided by the issuer, not by a claim an identity provider could also emit. The bearer layer
    /// binds the local signing key to the local issuer, so a token can only carry that issuer if we
    /// signed it.
    /// </summary>
    private bool TryGetLocallyIssuedUserId(ClaimsPrincipal principal, out Guid userId)
    {
        userId = Guid.Empty;

        var local = localLoginOptions.Value;

        // No signing key means password login was never registered, so no token is ours.
        if (string.IsNullOrWhiteSpace(local.SigningKey))
            return false;

        var issuer = principal.FindFirst("iss")?.Value;
        if (!string.Equals(issuer, local.Issuer, StringComparison.Ordinal))
            return false;

        var subject = principal.FindFirst("sub")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return Guid.TryParse(subject, out userId);
    }

    private async Task<ToamaisutaaUser> RunAsync(ExternalUserProfile profile, CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var providerKey = settings.ProviderKey;

        var login = await externalLoginStore.FindAsync(providerKey, profile.Subject, cancellationToken);

        var linkedUser = login is null
            ? null
            : await userStore.FindByIdAsync(login.UserId, cancellationToken)
              ?? throw new InvalidOperationException(
                  $"External login {login.Id} points at user {login.UserId}, which no longer exists.");

        var decision = policy.Decide(new ProvisioningContext
        {
            ProviderKey = providerKey,
            Profile = profile,
            SyncMode = settings.ProfileSyncMode,
            ExistingLogin = login,
            LinkedUser = linkedUser,
            LinkCandidate = null,
        });

        switch (decision.Action)
        {
            case ProvisioningAction.AlreadyLinked:
            {
                var user = linkedUser!;

                if (decision.ProfileNeedsUpdate)
                    await userStore.UpdateProfileAsync(user, profile, cancellationToken);

                if (ShouldStampSignIn(login!, settings.ProfileSyncMode, settings.SignInStampInterval))
                    await externalLoginStore.RecordSignInAsync(login!.Id, cancellationToken);

                return user;
            }

            case ProvisioningAction.LinkExisting:
            {
                var userId = decision.UserId
                    ?? throw new InvalidOperationException("A LinkExisting decision carried no user id.");

                var user = await userStore.FindByIdAsync(userId, cancellationToken)
                    ?? throw new InvalidOperationException($"A LinkExisting decision named user {userId}, which does not exist.");

                if (decision.ProfileNeedsUpdate)
                    await userStore.UpdateProfileAsync(user, profile, cancellationToken);

                await externalLoginStore.LinkAsync(user.Id, providerKey, profile, cancellationToken);
                return user;
            }

            case ProvisioningAction.CreateNew:
            {
                var user = await userStore.CreateAsync(profile, cancellationToken);
                await externalLoginStore.LinkAsync(user.Id, providerKey, profile, cancellationToken);
                return user;
            }

            default:
                throw new InvalidOperationException($"Unknown provisioning action '{decision.Action}'.");
        }
    }

    /// <summary>
    /// The sign-in stamp is the one thing that would otherwise write on every single request, which
    /// is the cost this whole design exists to avoid. Stamp it at most once per interval.
    /// </summary>
    private bool ShouldStampSignIn(ToamaisutaaExternalLogin login, ProfileSyncMode mode, TimeSpan interval) => mode switch
    {
        ProfileSyncMode.Never => false,
        ProfileSyncMode.EveryRequest => true,
        _ => login.LastSignInAt is not { } last || timeProvider.GetUtcNow() - last >= interval,
    };
}
