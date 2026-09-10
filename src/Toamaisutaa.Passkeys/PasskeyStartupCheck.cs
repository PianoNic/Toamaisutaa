using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// Refuses to start rather than failing at the first ceremony. A relying party id that is wrong is
/// invisible until a browser refuses to sign, and by then somebody is standing in front of a prompt
/// that will not go away.
/// </summary>
internal sealed class PasskeyStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaPasskeyOptions> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        CheckRelyingParty(settings, problems);
        CheckStores(problems);
        CheckCeremony(settings, problems);

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa passkeys are registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void CheckRelyingParty(ToamaisutaaPasskeyOptions settings, List<string> problems)
    {
        if (string.IsNullOrWhiteSpace(settings.RelyingPartyId))
        {
            problems.Add(
                "Passkeys:RelyingPartyId is not set. It is the domain every credential is bound to, and there is no "
                + "default because guessing it wrong is permanent: credentials registered against one value cannot be "
                + "re-bound to another. Set it to the site's domain alone - 'example.com', with no scheme and no port.");
        }
        else if (settings.RelyingPartyId.Contains("://", StringComparison.Ordinal)
            || settings.RelyingPartyId.Contains(':', StringComparison.Ordinal)
            || settings.RelyingPartyId.Contains('/', StringComparison.Ordinal))
        {
            problems.Add(
                $"Passkeys:RelyingPartyId is '{settings.RelyingPartyId}'. It must be a bare domain - no scheme, no "
                + "port, no path. The full origin belongs in Passkeys:Origins.");
        }

        if (settings.Origins.Count == 0)
        {
            problems.Add(
                "Passkeys:Origins is empty. Every ceremony is checked against it, so with nothing in it none can "
                + "succeed. Add the full origins the client is served from - 'https://example.com'.");
        }

        foreach (var origin in settings.Origins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out _))
                problems.Add($"Passkeys:Origins contains '{origin}', which is not an absolute URI. Include the scheme.");
        }
    }

    private void CheckStores(List<string> problems)
    {
        foreach (var storeType in new[] { typeof(IPasskeyCredentialStore), typeof(IPasskeyChallengeStore) })
        {
            if (!IsRegistered(storeType))
            {
                problems.Add(
                    $"No {storeType.Name} is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or "
                    + "AddToamaisutaaDbContext(...), or register the stores yourself.");
            }
        }

        if (!IsRegistered(typeof(IUserStore)))
            problems.Add($"No {nameof(IUserStore)} is registered, and a passkey sign-in has to resolve the account it names.");

        if (!IsRegistered(typeof(IAccessTokenIssuer)))
        {
            problems.Add(
                "No IAccessTokenIssuer is registered, so a verified passkey would have nothing to issue. Call "
                + "AddToamaisutaaPasswordLogin(configuration) and AddToamaisutaaBearer(configuration): a passkey "
                + "sign-in ends in the same locally issued token pair a password sign-in does.");
        }

        if (!IsRegistered(typeof(IRefreshTokenStore)))
            problems.Add("No IRefreshTokenStore is registered, and a passkey sign-in establishes a refresh family like any other.");
    }

    private static void CheckCeremony(ToamaisutaaPasskeyOptions settings, List<string> problems)
    {
        if (settings.ChallengeLifetime <= TimeSpan.Zero)
            problems.Add("Passkeys:ChallengeLifetime must be positive, or no ceremony could ever be completed.");

        if (settings.RegistrationProofWindow <= TimeSpan.Zero)
        {
            problems.Add(
                "Passkeys:RegistrationProofWindow must be positive, or a second factor could never stand in for the "
                + "current password and an account without a password could never register a credential.");
        }

        if (settings.MaxCredentialsPerUser < 0)
            problems.Add($"Passkeys:MaxCredentialsPerUser is {settings.MaxCredentialsPerUser}; use 0 for unlimited.");
    }

    private bool IsRegistered(Type serviceType)
    {
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == serviceType)
                return true;
        }

        return false;
    }
}
