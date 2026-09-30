using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Refuses to start outside Development on a key the sample publishes.
/// </summary>
/// <remarks>
/// The sample's signing key, pepper and two-factor key sit in a public repository so that it runs
/// with nothing configured. A deployment that copied its Development settings, or runs as
/// Development, signs tokens anyone can forge and encrypts TOTP secrets anyone can read. Every other
/// check here passes those values: they are the right length and valid base64. Kept as SHA-256
/// fingerprints so this file does not become a second place they are published.
/// </remarks>
internal sealed class PublishedSecretsStartupCheck(IServiceProvider provider, IHostEnvironment environment) : IHostedService
{
    private static readonly HashSet<string> Published = new(StringComparer.Ordinal)
    {
        // samples/MinimalApiSample: the public half of LocalLogin:SigningKeys "sample-2026-09".
        "CB3FE4F2453FCAE878E5685739D719F4BF6F3DD25D685578B20DC9EF8CF8D73E",

        // samples/MinimalApiSample: LocalLogin:Pepper, decoded.
        "5004DD2B0E5F0F2C5E1D0CC2A50E239E532520489D130279C0F7476949FFA2BE",

        // samples/MinimalApiSample: TwoFactor:EncryptionKey, decoded.
        "0C0E3BE6BCDA07D83FC37F6ABDC900E3BC847925FC9639D9F53258776B36138B",
    };

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (environment.IsDevelopment())
            return Task.CompletedTask;

        var problems = new List<string>();
        var local = provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>().Value;
        var twoFactor = provider.GetRequiredService<IOptions<ToamaisutaaTwoFactorOptions>>().Value;

        foreach (var key in provider.GetService<LocalSigningKeyRing>()?.Keys ?? [])
        {
            if (IsPublished(key.Key.ExportSubjectPublicKeyInfo()))
                problems.Add($"LocalLogin:SigningKeys entry '{key.KeyId}' is the sample's published key. Anyone can sign tokens with it.");
        }

        if (IsPublishedBase64(local.Pepper) || local.RetiredPeppers.Values.Any(IsPublishedBase64))
            problems.Add("LocalLogin:Pepper (or a retired one) is the sample's published pepper.");

        if (IsPublishedBase64(twoFactor.EncryptionKey) || twoFactor.RetiredEncryptionKeys.Values.Any(IsPublishedBase64))
            problems.Add("TwoFactor:EncryptionKey (or a retired one) is the sample's published key. Anyone can decrypt the stored TOTP secrets.");

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                $"Toamaisutaa refuses to start in the {environment.EnvironmentName} environment with values from the public sample. "
                + "Generate your own and set them from the environment or a secret store:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static bool IsPublished(byte[] material) => Published.Contains(Convert.ToHexString(SHA256.HashData(material)));

    private static bool IsPublishedBase64(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        try
        {
            return IsPublished(Convert.FromBase64String(value));
        }
        catch (FormatException)
        {
            // Reported by the check that owns the setting.
            return false;
        }
    }
}
