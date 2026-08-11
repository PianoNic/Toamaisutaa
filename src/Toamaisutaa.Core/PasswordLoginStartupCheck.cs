using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Refuses to start rather than failing on the first login. Everything here is a misconfiguration
/// that is invisible until someone tries to sign in, which is the worst time to discover it.
/// </summary>
internal sealed class PasswordLoginStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    IOptions<ToamaisutaaOidcOptions> oidcOptions,
    DummyPasswordHash dummy) : IHostedService
{
    private const int MinimumSigningKeyBytes = 32;
    private const int MinimumPepperBytes = 32;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        CheckRegistrations(problems);
        CheckSigningKey(settings, problems);
        CheckPeppers(settings, problems);
        CheckHashingParameters(settings, problems);
        CheckLengths(settings, problems);

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa password login is registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        // Compute the placeholder hash now, so the first sign-in against an unknown identifier is
        // not the one request that pays for it and stands out on the clock.
        dummy.Warm();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private void CheckRegistrations(List<string> problems)
    {
        if (!IsRegistered(typeof(IPasswordResetNotifier)))
        {
            problems.Add(
                $"No {nameof(IPasswordResetNotifier)} is registered. Password reset hands the token to it, and this "
                + "package deliberately ships no email implementation - register one of your own.");
        }

        if (!IsRegistered(typeof(IAccessTokenIssuer)))
        {
            problems.Add(
                $"No {nameof(IAccessTokenIssuer)} is registered. Call AddToamaisutaaBearer(...): a local sign-in issues "
                + "a token that the bearer layer then validates, so both halves have to be present.");
        }

        foreach (var storeType in new[]
                 {
                     typeof(IUserStore),
                     typeof(IPasswordCredentialStore),
                     typeof(IRefreshTokenStore),
                     typeof(IPasswordResetTokenStore),
                 })
        {
            if (!IsRegistered(storeType))
            {
                problems.Add(
                    $"No {storeType.Name} is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or "
                    + "AddToamaisutaaDbContext(...), or register the stores yourself.");
            }
        }
    }

    private static void CheckSigningKey(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        if (string.IsNullOrWhiteSpace(settings.SigningKey))
        {
            problems.Add(
                "LocalLogin:SigningKey is not set. Locally issued access tokens are signed with it, and there is no "
                + "generated fallback on purpose: a per-process key would sign people out on every restart and "
                + "disagree between instances.");
            return;
        }

        if (!TryDecode(settings.SigningKey, out var key))
        {
            problems.Add("LocalLogin:SigningKey is not valid base64.");
            return;
        }

        if (key.Length < MinimumSigningKeyBytes)
            problems.Add($"LocalLogin:SigningKey decodes to {key.Length} bytes; HMAC-SHA256 needs at least {MinimumSigningKeyBytes}.");
    }

    private static void CheckPeppers(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        if (settings.PepperVersion.Length == 0 || !settings.PepperVersion.All(char.IsLetterOrDigit))
            problems.Add("LocalLogin:PepperVersion must be a non-empty alphanumeric marker; it is written into every stored hash.");

        if (!string.IsNullOrWhiteSpace(settings.Pepper))
        {
            if (!TryDecode(settings.Pepper, out var pepper))
                problems.Add("LocalLogin:Pepper is not valid base64.");
            else if (pepper.Length < MinimumPepperBytes)
                problems.Add($"LocalLogin:Pepper decodes to {pepper.Length} bytes; use at least {MinimumPepperBytes}.");
        }

        foreach (var (version, encoded) in settings.RetiredPeppers)
        {
            if (version.Length == 0 || !version.All(char.IsLetterOrDigit))
                problems.Add($"LocalLogin:RetiredPeppers has the key '{version}', which is not an alphanumeric version marker.");

            if (!TryDecode(encoded, out _))
                problems.Add($"LocalLogin:RetiredPeppers['{version}'] is not valid base64.");
        }

        if (!string.IsNullOrWhiteSpace(settings.Pepper) && settings.RetiredPeppers.ContainsKey(settings.PepperVersion))
        {
            problems.Add(
                $"LocalLogin:RetiredPeppers contains '{settings.PepperVersion}', which is also the active version. "
                + "Give the new pepper a new version marker, or rows written under it cannot be told apart.");
        }
    }

    private static void CheckHashingParameters(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        var defaults = new ToamaisutaaLocalLoginOptions();

        if (settings.Pbkdf2Iterations < defaults.Pbkdf2Iterations)
            problems.Add($"LocalLogin:Pbkdf2Iterations is {settings.Pbkdf2Iterations}; {defaults.Pbkdf2Iterations} is the documented floor.");

        if (settings.SaltSizeBytes < defaults.SaltSizeBytes)
            problems.Add($"LocalLogin:SaltSizeBytes is {settings.SaltSizeBytes}; {defaults.SaltSizeBytes} is the floor.");

        if (settings.HashSizeBytes < defaults.HashSizeBytes)
            problems.Add($"LocalLogin:HashSizeBytes is {settings.HashSizeBytes}; {defaults.HashSizeBytes} is the floor.");
    }

    private void CheckLengths(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        if (settings.MaximumPasswordLength < settings.MinimumPasswordLength)
            problems.Add("LocalLogin:MaximumPasswordLength is below LocalLogin:MinimumPasswordLength, so no password could ever be accepted.");

        var oidc = oidcOptions.Value;

        if (oidc.ValidateAudience
            && string.IsNullOrWhiteSpace(settings.Audience)
            && string.IsNullOrWhiteSpace(oidc.ClientId))
        {
            problems.Add(
                "Audience validation is on but neither LocalLogin:Audience nor Oidc:ClientId is set, so every locally "
                + "issued token would be rejected by the bearer layer that just issued it.");
        }
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
