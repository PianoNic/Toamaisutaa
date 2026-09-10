using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>
/// The Pwned Passwords range API, queried by k-anonymity: five characters of the hash go out, the
/// other thirty-five are compared here.
/// </summary>
/// <remarks>
/// SHA-1 is not a choice - it is the corpus's index, and the whole point is that nothing about the
/// password can be recovered from five hex characters. A prefix matches on the order of eight
/// hundred hashes, so the service learns that somebody typed one of eight hundred things and
/// nothing about which.
/// </remarks>
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

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(new Uri(settings.ApiBaseAddress), $"range/{prefix}"));

        request.Headers.TryAddWithoutValidation("User-Agent", settings.UserAgent);

        // Pads the response with entries whose count is zero, so its length no longer says how many
        // real hashes share the prefix. The padding drops out on its own: a zero count never
        // reaches a threshold of one or more.
        request.Headers.TryAddWithoutValidation("Add-Padding", "true");

        // The options timeout rather than the client's, so changing it in configuration takes effect
        // without the named client being rebuilt.
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
}
