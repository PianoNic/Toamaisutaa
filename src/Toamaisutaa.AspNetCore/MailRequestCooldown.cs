using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// One reset or magic-link request per address per <c>LocalLogin:MailRequestCooldown</c>.
/// </summary>
/// <remarks>
/// The rate limiter counts per caller, which does nothing for one inbox asked about from many
/// addresses: each request mailed another link and retired the last, so the owner's inbox filled
/// and none of their links survived long enough to use. Keyed by the address asked about, whether
/// or not it has an account, so the cooldown answers nothing about which ones do. Held per process:
/// behind several instances the ceiling is one per instance, which is still a ceiling.
/// </remarks>
internal sealed class MailRequestCooldown(IOptions<ToamaisutaaLocalLoginOptions> options, TimeProvider timeProvider)
{
    /// <summary>Past this many remembered addresses, the expired ones are swept on the next call.</summary>
    private const int SweepThreshold = 10_000;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastRequested = new(StringComparer.Ordinal);

    /// <summary>True when a request for <paramref name="email"/> may go ahead now.</summary>
    internal bool TryEnter(string purpose, string email)
    {
        var cooldown = options.Value.MailRequestCooldown;
        if (cooldown <= TimeSpan.Zero)
            return true;

        var now = timeProvider.GetUtcNow();

        if (_lastRequested.Count > SweepThreshold)
        {
            foreach (var (key, at) in _lastRequested)
            {
                if (now - at >= cooldown)
                    _lastRequested.TryRemove(key, out _);
            }
        }

        var address = Key(purpose, email);

        while (true)
        {
            if (_lastRequested.TryGetValue(address, out var last))
            {
                if (now - last < cooldown)
                    return false;

                if (_lastRequested.TryUpdate(address, now, last))
                    return true;
            }
            else if (_lastRequested.TryAdd(address, now))
            {
                return true;
            }
        }
    }

    /// <summary>Hands back an entry taken for a request that ended up sending nothing, so a mistyped
    /// password does not cost the person a minute.</summary>
    internal void Release(string purpose, string email) => _lastRequested.TryRemove(Key(purpose, email), out _);

    private static string Key(string purpose, string email) => $"{purpose}:{Normalizer.Normalize(email)}";
}
