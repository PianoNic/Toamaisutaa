using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class PasswordLoginStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    IOptions<ToamaisutaaOidcOptions> oidcOptions,
    DummyPasswordHash dummy,
    LocalSigningKeyRing signingKeys) : IHostedService
{
    private const int MinimumSigningKeyBytes = 32;
    private const int MinimumPepperBytes = 32;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        CheckRegistrations(problems);
        CheckEmailVerification(settings, problems);
        CheckSigningKeys(settings, problems);
        CheckPeppers(settings, problems);
        CheckHashingParameters(settings, problems);
        CheckLengths(settings, problems);
        CheckNat64Prefixes(settings, problems);
        CheckSharedNetworks(settings, problems);

        if (problems.Count > 0)
            throw StartupProblems.Refusal("Toamaisutaa password login is registered but not usable:", problems);

        // Warmed now so the first unknown-identifier sign-in does not stand out on the clock.
        dummy.Warm();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void CheckNat64Prefixes(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        foreach (var value in settings.RateLimit.Nat64Prefixes)
        {
            if (!Nat64Prefix.TryParse(value, out _))
            {
                problems.Add(
                    $"LocalLogin:RateLimit:Nat64Prefixes has '{value}', which is not an IPv6 prefix of length 32, 40, 48, 56, 64 or 96.");
            }
        }
    }

    private static void CheckSharedNetworks(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        foreach (var value in settings.RateLimit.SharedNetworks)
        {
            if (!System.Net.IPNetwork.TryParse(value, out _))
                problems.Add($"LocalLogin:RateLimit:SharedNetworks has '{value}', which is not a network in CIDR form such as 203.0.113.7/32.");
        }
    }

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
                     typeof(IInvitationTokenStore),
                     typeof(IEmailVerificationTokenStore),
                     typeof(IMagicLinkTokenStore),
                     typeof(ISignInThrottleStore),
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

    private void CheckEmailVerification(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        if (settings.RequireVerifiedEmailForPasswordReset && !IsRegistered(typeof(IEmailVerificationNotifier)))
        {
            problems.Add(
                $"LocalLogin:RequireVerifiedEmailForPasswordReset is on (the default) but no {nameof(IEmailVerificationNotifier)} "
                + "is registered, so no address can ever be verified and no password can ever be reset. Register one, or "
                + "set LocalLogin:RequireVerifiedEmailForPasswordReset to false.");
        }

        if (IsRegistered(typeof(IMagicLinkNotifier)) && !IsRegistered(typeof(IEmailVerificationNotifier)))
        {
            problems.Add(
                $"An {nameof(IMagicLinkNotifier)} is registered but no {nameof(IEmailVerificationNotifier)} is. A magic "
                + "link is only ever sent to a verified address, so no address could ever qualify and /auth/magic-link "
                + "would answer 204 without sending anything. Register one, or drop the magic-link notifier.");
        }

        if (settings.RequireVerifiedEmailForSignIn)
            CheckSignInVerification(problems);
    }

    private void CheckSigningKeys(ToamaisutaaLocalLoginOptions settings, List<string> problems)
    {
        problems.AddRange(signingKeys.Problems);

        var hasSymmetric = !string.IsNullOrWhiteSpace(settings.SigningKey);

        if (!hasSymmetric && settings.SigningKeys.Count == 0)
        {
            problems.Add(
                "Neither LocalLogin:SigningKey nor LocalLogin:SigningKeys is set. Locally issued access tokens are "
                + "signed with one of them, and there is no generated fallback on purpose: a per-process key would "
                + "sign people out on every restart and disagree between instances.");
            return;
        }

        // Checked even when inactive: alongside an asymmetric list it still validates HS256 tokens
        // issued before the switch.
        if (!hasSymmetric)
            return;

        if (!TryDecode(settings.SigningKey!, out var key))
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

        if (settings.Pbkdf2Iterations > Pbkdf2PasswordHasher.MaxIterations)
        {
            problems.Add(
                $"LocalLogin:Pbkdf2Iterations is {settings.Pbkdf2Iterations}; {Pbkdf2PasswordHasher.MaxIterations} is "
                + "the highest a stored row may name, so every row written with it would fail to verify.");
        }

        if (settings.HashSizeBytes > Pbkdf2PasswordHasher.MaxHashSizeBytes)
        {
            problems.Add(
                $"LocalLogin:HashSizeBytes is {settings.HashSizeBytes}; {Pbkdf2PasswordHasher.MaxHashSizeBytes} is the "
                + "highest a stored row may carry, so every row written with it would fail to verify.");
        }
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

    private void CheckSignInVerification(List<string> problems)
    {
        if (!IsRegistered(typeof(IEmailVerificationChallengeStore)))
        {
            problems.Add(
                $"LocalLogin:RequireVerifiedEmailForSignIn is on but no {nameof(IEmailVerificationChallengeStore)} is registered. "
                + "Call AddToamaisutaaEntityFrameworkStores<TContext>() or AddToamaisutaaDbContext(...), or register one yourself.");
        }

        // The last registration is the one resolved; anything but the default brings its own delivery.
        var method = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IEmailVerificationMethod));
        if (method?.ImplementationType != typeof(EmailVerificationCodeMethod))
            return;

        if (!IsRegistered(typeof(IEmailVerificationCodeStore)))
        {
            problems.Add(
                $"LocalLogin:RequireVerifiedEmailForSignIn is on with the default code method but no {nameof(IEmailVerificationCodeStore)} "
                + "is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or AddToamaisutaaDbContext(...), or register one yourself.");
        }

        var notifier = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IEmailVerificationNotifier));

        if (notifier is null)
        {
            problems.Add(
                $"LocalLogin:RequireVerifiedEmailForSignIn is on but no {nameof(IEmailVerificationNotifier)} is registered, so no "
                + "verification code could be sent and no unverified account could ever sign in. Register one, register an "
                + $"{nameof(IEmailVerificationMethod)} of your own, or turn the option off.");
        }
        else if (NotifierType(notifier) is { } type && !ImplementsSendCode(type))
        {
            problems.Add(
                $"LocalLogin:RequireVerifiedEmailForSignIn is on but {type.Name} does not implement "
                + $"{nameof(IEmailVerificationNotifier)}.{nameof(IEmailVerificationNotifier.SendCodeAsync)}, so no verification code could "
                + $"be sent. Implement it, register an {nameof(IEmailVerificationMethod)} of your own, or turn the option off.");
        }
    }

    /// <summary>Null for a factory registration, whose type is not known until it runs.</summary>
    private static Type? NotifierType(ServiceDescriptor descriptor) =>
        descriptor.IsKeyedService ? null : descriptor.ImplementationType ?? descriptor.ImplementationInstance?.GetType();

    private static bool ImplementsSendCode(Type type)
    {
        var map = type.GetInterfaceMap(typeof(IEmailVerificationNotifier));
        var index = Array.FindIndex(map.InterfaceMethods, method => method.Name == nameof(IEmailVerificationNotifier.SendCodeAsync));

        return index >= 0 && map.TargetMethods[index].DeclaringType != typeof(IEmailVerificationNotifier);
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
