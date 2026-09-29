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
    /// <summary>The longest address RFC 5321 allows. Anything longer names no mailbox, and was
    /// only ever a way to pin megabytes in this dictionary.</summary>
    internal const int MaxAddressLength = 254;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastRequested = new(StringComparer.Ordinal);
    private long _lastSweepTicks;

    /// <summary>True when a request for <paramref name="email"/> may go ahead now. Always false for
    /// something too long to be an address, which is dropped rather than remembered.</summary>
    internal bool TryEnter(string purpose, string email)
    {
        if (email.Length > MaxAddressLength)
            return false;

        var cooldown = options.Value.MailRequestCooldown;
        if (cooldown <= TimeSpan.Zero)
            return true;

        var now = timeProvider.GetUtcNow();
        Sweep(now, cooldown);

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

    /// <summary>The count this holds for testing: what is remembered right now.</summary>
    internal int Count => _lastRequested.Count;

    // Once a window, whatever the count. Sweeping only past a threshold left everything below it in
    // memory for the life of the process. What is left is at most one window of requests.
    private void Sweep(DateTimeOffset now, TimeSpan cooldown)
    {
        var last = Interlocked.Read(ref _lastSweepTicks);

        if (now.UtcTicks - last < cooldown.Ticks || Interlocked.CompareExchange(ref _lastSweepTicks, now.UtcTicks, last) != last)
            return;

        foreach (var (key, at) in _lastRequested)
        {
            if (now - at >= cooldown)
                _lastRequested.TryRemove(key, out _);
        }
    }

    // Hashed, so an entry costs the same whatever the caller sent.
    private static string Key(string purpose, string email) =>
        $"{purpose}:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Normalizer.Normalize(email))))}";
}
