using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Refuses to start rather than failing at enrolment. Everything checked here is invisible until
/// somebody tries to turn two-factor on, which is the worst moment to find out.
/// </summary>
internal sealed class TwoFactorStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaTwoFactorOptions> options) : IHostedService
{
    private const int RequiredEncryptionKeyBytes = 32;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        CheckEnforcementPath(problems);
        CheckStores(problems);
        CheckEncryptionKeys(settings, problems);
        CheckTotpParameters(settings, problems);
        CheckRecoveryCodes(settings, problems);

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa two-factor authentication is registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// A second factor needs somewhere to apply. Local sign-in gives it the challenge step; the
    /// claims transformation gives it a policy over identity-provider tokens. With neither, users
    /// can enrol into something that will never be asked for, and nothing else will ever say so.
    /// </summary>
    private void CheckEnforcementPath(List<string> problems)
    {
        var hasPasswordLogin = IsRegistered(typeof(IPasswordSignInService));
        var hasClaimsTransformation = services.Any(descriptor =>
            descriptor.ServiceType.FullName == "Microsoft.AspNetCore.Authentication.IClaimsTransformation"
            && descriptor.ImplementationType?.Name == "TwoFactorClaimsTransformation");

        if (hasPasswordLogin || hasClaimsTransformation)
            return;

        problems.Add(
            "AddToamaisutaaTwoFactor() is registered, but neither AddToamaisutaaPasswordLogin() nor "
            + "AddToamaisutaaTwoFactorClaims() is. Nothing would ever ask for the second factor: local sign-in is what "
            + "issues the challenge, and the claims transformation is what lets a policy see an enrolment on an "
            + "identity provider's token. Users could enrol, receive recovery codes, and never be challenged. "
            + "Add AddToamaisutaaPasswordLogin(configuration) if this application signs users in with a password, or "
            + "AddToamaisutaaTwoFactorClaims() if it only accepts tokens from an identity provider - or both if it "
            + "does both.");
    }

    private void CheckStores(List<string> problems)
    {
        foreach (var storeType in new[] { typeof(ITwoFactorStore), typeof(IRecoveryCodeStore), typeof(ITwoFactorChallengeStore) })
        {
            if (!IsRegistered(storeType))
            {
                problems.Add(
                    $"No {storeType.Name} is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or "
                    + "AddToamaisutaaDbContext(...), or register the stores yourself.");
            }
        }

        if (!IsRegistered(typeof(IUserStore)))
            problems.Add($"No {nameof(IUserStore)} is registered, and the security stamp that ends old sessions lives on the user row.");
    }

    private static void CheckEncryptionKeys(ToamaisutaaTwoFactorOptions settings, List<string> problems)
    {
        if (string.IsNullOrWhiteSpace(settings.EncryptionKey))
        {
            problems.Add(
                "TwoFactor:EncryptionKey is not set. TOTP secrets are encrypted at rest with it, and there is no "
                + "generated fallback on purpose: a per-process key would make every enrolment unreadable after a "
                + "restart, and a TOTP secret cannot be re-derived - those users would have to enrol again.");
        }
        else if (!TryDecode(settings.EncryptionKey, out var key))
        {
            problems.Add("TwoFactor:EncryptionKey is not valid base64.");
        }
        else if (key.Length != RequiredEncryptionKeyBytes)
        {
            problems.Add($"TwoFactor:EncryptionKey decodes to {key.Length} bytes; AES-256-GCM needs exactly {RequiredEncryptionKeyBytes}.");
        }

        if (string.IsNullOrWhiteSpace(settings.EncryptionKeyVersion))
            problems.Add("TwoFactor:EncryptionKeyVersion must be set; it is stamped on every row the active key encrypts.");

        foreach (var (version, encoded) in settings.RetiredEncryptionKeys)
        {
            if (!TryDecode(encoded, out var retired))
                problems.Add($"TwoFactor:RetiredEncryptionKeys['{version}'] is not valid base64.");
            else if (retired.Length != RequiredEncryptionKeyBytes)
                problems.Add($"TwoFactor:RetiredEncryptionKeys['{version}'] decodes to {retired.Length} bytes; AES-256-GCM needs exactly {RequiredEncryptionKeyBytes}.");
        }

        if (!string.IsNullOrWhiteSpace(settings.EncryptionKey)
            && settings.RetiredEncryptionKeys.ContainsKey(settings.EncryptionKeyVersion))
        {
            problems.Add(
                $"TwoFactor:RetiredEncryptionKeys contains '{settings.EncryptionKeyVersion}', which is also the active "
                + "version. Give the new key a new version marker, or rows written under it cannot be told apart.");
        }
    }

    private static void CheckTotpParameters(ToamaisutaaTwoFactorOptions settings, List<string> problems)
    {
        if (settings.Digits is < 6 or > 8)
            problems.Add($"TwoFactor:Digits is {settings.Digits}; RFC 4226 allows 6 to 8, and authenticator apps assume 6.");

        if (settings.Period <= TimeSpan.Zero)
            problems.Add("TwoFactor:Period must be positive.");

        if (settings.DriftSteps < 0)
            problems.Add($"TwoFactor:DriftSteps is {settings.DriftSteps}; it cannot be negative.");

        if (settings.SecretSizeBytes < 16)
            problems.Add($"TwoFactor:SecretSizeBytes is {settings.SecretSizeBytes}; RFC 4226 requires at least 16 and recommends 20.");

        if (settings.ChallengeLifetime <= TimeSpan.Zero)
            problems.Add("TwoFactor:ChallengeLifetime must be positive, or no challenge could ever be completed.");
    }

    private static void CheckRecoveryCodes(ToamaisutaaTwoFactorOptions settings, List<string> problems)
    {
        if (settings.RecoveryCodeCount < 1)
            problems.Add($"TwoFactor:RecoveryCodeCount is {settings.RecoveryCodeCount}; a user with no recovery codes who loses their device loses the account.");

        if (settings.RecoveryCodeLowWaterMark >= settings.RecoveryCodeCount)
            problems.Add("TwoFactor:RecoveryCodeLowWaterMark is at or above RecoveryCodeCount, so every redemption would warn.");
    }

    private static bool TryDecode(string value, out byte[] decoded)
    {
        decoded = [];

        try
        {
            decoded = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
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
