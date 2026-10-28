using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

internal sealed partial class ExternalLoginStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaExternalLoginOptions> options,
    IHostEnvironment environment) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;

        // None configured is a supported deployment: no SSO, nothing mapped.
        if (settings.Providers.Count == 0)
            return Task.CompletedTask;

        var problems = new List<string>();

        foreach (var (key, provider) in settings.Providers)
            CheckProvider(key, provider, problems);

        CheckReturnUrls(settings, problems);
        CheckLifetimes(settings, problems);
        CheckServices(problems);

        if (problems.Count > 0)
            throw StartupProblems.Refusal("Toamaisutaa external login has providers configured but is not usable:", problems);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private void CheckProvider(string key, ToamaisutaaExternalProviderOptions provider, List<string> problems)
    {
        var section = $"ExternalLogin:Providers:{key}";

        if (!ProviderKey().IsMatch(key))
            problems.Add($"'{key}' is not a usable provider key. It goes into routes, so use letters, digits, '-' and '_', at most 64.");

        if (!Uri.TryCreate(provider.Authority, UriKind.Absolute, out var authority))
        {
            problems.Add($"{section}:Authority is '{provider.Authority}', which is not an absolute URI. Use the issuer, such as 'https://accounts.google.com'.");
        }
        else if (authority.Scheme != Uri.UriSchemeHttps && !environment.IsDevelopment())
        {
            problems.Add($"{section}:Authority is '{provider.Authority}'. Outside Development it must be https, or its keys and tokens travel in the clear.");
        }

        if (string.IsNullOrWhiteSpace(provider.ClientId))
            problems.Add($"{section}:ClientId is not set. It is the id the provider issued when this application was registered there.");

        if (!provider.Scopes.Contains("openid", StringComparer.Ordinal))
            problems.Add($"{section}:Scopes does not include 'openid', so the provider would return no ID token to sign in with.");
    }

    private static void CheckReturnUrls(ToamaisutaaExternalLoginOptions settings, List<string> problems)
    {
        if (settings.AllowedReturnUrls.Count == 0)
        {
            problems.Add(
                "ExternalLogin:AllowedReturnUrls is empty, so no sign-in could ever hand its code back. Add the page or "
                + "app link that finishes sign-in, such as 'https://app.example.com/auth/callback' or 'myapp://auth/callback'.");
        }

        foreach (var returnUrl in settings.AllowedReturnUrls)
        {
            if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var parsed))
            {
                problems.Add($"ExternalLogin:AllowedReturnUrls contains '{returnUrl}', which is not an absolute URI.");
                continue;
            }

            if (parsed.Fragment.Length > 0 || returnUrl.Contains('#', StringComparison.Ordinal))
                problems.Add($"ExternalLogin:AllowedReturnUrls contains '{returnUrl}'. Drop the fragment: the code is appended as a query parameter.");

            if (parsed.Scheme == Uri.UriSchemeHttp && !parsed.IsLoopback)
                problems.Add($"ExternalLogin:AllowedReturnUrls contains '{returnUrl}'. Plain http is only allowed for localhost, since the URL carries a sign-in code.");
        }

        if (settings.CallbackBaseUrl is { } callback
            && (!Uri.TryCreate(callback, UriKind.Absolute, out var callbackUri) || (callbackUri.Scheme != Uri.UriSchemeHttps && callbackUri.Scheme != Uri.UriSchemeHttp)))
        {
            problems.Add($"ExternalLogin:CallbackBaseUrl is '{callback}'. It must be the absolute http(s) address this application is reached on.");
        }
    }

    private static void CheckLifetimes(ToamaisutaaExternalLoginOptions settings, List<string> problems)
    {
        if (settings.RequestLifetime <= TimeSpan.Zero)
            problems.Add("ExternalLogin:RequestLifetime must be positive, or no sign-in could come back from the provider in time.");

        if (settings.ExchangeCodeLifetime <= TimeSpan.Zero)
            problems.Add("ExternalLogin:ExchangeCodeLifetime must be positive, or no code could ever be exchanged.");

        if (settings.LinkProofWindow <= TimeSpan.Zero)
            problems.Add("ExternalLogin:LinkProofWindow must be positive, or an account with no password could never link a provider.");
    }

    private void CheckServices(List<string> problems)
    {
        foreach (var storeType in new[] { typeof(IExternalLoginRequestStore), typeof(IExternalLoginStore), typeof(IUserStore), typeof(IRefreshTokenStore) })
        {
            if (!IsRegistered(storeType))
            {
                problems.Add(
                    $"No {storeType.Name} is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or "
                    + "AddToamaisutaaDbContext(...), or register the stores yourself.");
            }
        }

        if (!IsRegistered(typeof(IAccessTokenIssuer)))
        {
            problems.Add(
                "No IAccessTokenIssuer is registered, so a provider's sign-in would have nothing to issue. Call "
                + "AddToamaisutaaPasswordLogin(configuration) and AddToamaisutaaBearer(configuration): an external "
                + "sign-in ends in the same locally issued token pair a password sign-in does.");
        }

        // Every anonymous /start writes a row, so without the sweep the table grows as fast as anyone calls it.
        if (!services.Any(descriptor => descriptor.ImplementationType == typeof(TokenCleanupService)))
        {
            problems.Add(
                "External login is configured but expired sign-ins are never deleted: every anonymous /start writes a "
                + "row. Call AddToamaisutaaTokenCleanup().");
        }
    }

    private bool IsRegistered(Type serviceType) => services.Any(descriptor => descriptor.ServiceType == serviceType);

    [GeneratedRegex("^[A-Za-z0-9_-]{1,64}$")]
    private static partial Regex ProviderKey();
}
