using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

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
        // A locally issued token has no external login behind it; on the normal path every request
        // would provision another duplicate user.
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
            // Lost a race to create the same subject; the winner's row now exists, so one retry
            // takes the AlreadyLinked path.
            logger.LogDebug(
                exception,
                "Concurrent first sign-in for provider {ProviderKey}; re-reading the row the other request created.",
                options.Value.ProviderKey);

            try
            {
                return await RunAsync(profile, cancellationToken);
            }
            catch (ExternalLoginConflictException again)
            {
                throw new InvalidOperationException(
                    $"Cannot provision subject '{profile.Subject}' for provider '{options.Value.ProviderKey}': the database "
                    + "treats it as equal to an existing subject that differs only in case or accents. OIDC subjects are "
                    + "case-sensitive; give ToamaisutaaExternalLogins.Subject a case- and accent-sensitive collation "
                    + "(utf8mb4_bin on MySQL, Latin1_General_100_BIN2 on SQL Server). The shipped migrations do this; a "
                    + "context of your own needs ApplyToamaisutaaConfiguration(Database) and a new migration.",
                    again);
            }
        }
    }

    /// <summary>
    /// Decided by the issuer, not a claim an identity provider could also emit: the bearer layer binds
    /// the local signing key to the local issuer.
    /// </summary>
    private bool TryGetLocallyIssuedUserId(ClaimsPrincipal principal, out Guid userId)
    {
        userId = Guid.Empty;

        var local = localLoginOptions.Value;

        // Both key shapes are checked: an asymmetric-only deployment has no SigningKey, and reading
        // only that would provision every locally issued token as a stranger.
        if (string.IsNullOrWhiteSpace(local.SigningKey) && local.SigningKeys.Count == 0)
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

    /// <summary>Throttled so the sign-in stamp does not write on every request.</summary>
    private bool ShouldStampSignIn(ToamaisutaaExternalLogin login, ProfileSyncMode mode, TimeSpan interval) => mode switch
    {
        ProfileSyncMode.Never => false,
        ProfileSyncMode.EveryRequest => true,
        _ => login.LastSignInAt is not { } last || timeProvider.GetUtcNow() - last >= interval,
    };
}
