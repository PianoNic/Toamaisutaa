using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>
/// The Pwned Passwords range API, queried by k-anonymity. SHA-1 is not a choice: it is the corpus's
/// index.
/// </summary>
internal sealed class PwnedPasswordsRangeIndex(
    IHttpClientFactory httpClientFactory,
    IOptions<ToamaisutaaHibpOptions> options) : IBreachedPasswordIndex
{
    private const int PrefixLength = 5;

    public async ValueTask<int> CountAsync(string password, CancellationToken cancellationToken = default)
    {
        var settings = options.Value;

        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..PrefixLength];
        var suffix = hash[PrefixLength..];

        using var request = new HttpRequestMessage(HttpMethod.Get, Range(settings.ApiBaseAddress, prefix));

        request.Headers.TryAddWithoutValidation("User-Agent", settings.UserAgent);

        // Zero-count padding hides how many real hashes share the prefix, and never reaches a
        // threshold of one.
        request.Headers.TryAddWithoutValidation("Add-Padding", "true");

        // The options timeout rather than the client's, so a configuration change takes effect
        // without rebuilding the named client.
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        attempt.CancelAfter(settings.Timeout);

        var client = httpClientFactory.CreateClient(ToamaisutaaHibpDefaults.HttpClientName);

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, attempt.Token);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(attempt.Token);
        using var reader = new StreamReader(stream);

        while (await reader.ReadLineAsync(attempt.Token) is { } line)
        {
            var separator = line.IndexOf(':', StringComparison.Ordinal);

            if (separator != suffix.Length || !line.AsSpan(0, separator).Equals(suffix, StringComparison.OrdinalIgnoreCase))
                continue;

            return int.TryParse(line.AsSpan(separator + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
                ? count
                : 0;
        }

        return 0;
    }

    /// <summary>
    /// Without the trailing slash, resolving drops the base's last segment, so a mirror at
    /// <c>/pwned</c> would 404 and silently fail open on every password.
    /// </summary>
    private static Uri Range(string baseAddress, string prefix)
    {
        var root = baseAddress.EndsWith('/') ? baseAddress : baseAddress + "/";

        return new Uri(new Uri(root), $"range/{prefix}");
    }
}
