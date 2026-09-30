using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Keyed by the address asked about, whether or not it has an account, so the per-caller rate limiter
/// cannot be sidestepped from many IPs and the cooldown reveals nothing about which addresses exist.
/// </summary>
internal sealed class MailRequestCooldown(IOptions<ToamaisutaaLocalLoginOptions> options, TimeProvider timeProvider)
{
    /// <summary>The longest address RFC 5321 allows; anything longer could only pin memory here.</summary>
    internal const int MaxAddressLength = 254;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastRequested = new(StringComparer.Ordinal);
    private long _lastSweepTicks;

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

    /// <summary>Hands back an entry for a request that sent nothing, so a mistyped password does not
    /// cost the person a cooldown.</summary>
    internal void Release(string purpose, string email) => _lastRequested.TryRemove(Key(purpose, email), out _);

    internal TimeSpan Period => options.Value.MailRequestCooldown;

    internal int Count => _lastRequested.Count;

    // Once a window whatever the count, since a size threshold leaves everything below it in memory forever.
    private void Sweep(DateTimeOffset now, TimeSpan cooldown)
    {
        var last = Interlocked.Read(ref _lastSweepTicks);

        if (now.UtcTicks - last < cooldown.Ticks || Interlocked.CompareExchange(ref _lastSweepTicks, now.UtcTicks, last) != last)
            return;

        foreach (var entry in _lastRequested)
        {
            if (now - entry.Value < cooldown)
                continue;

            BeforeSweepRemoves?.Invoke(entry.Key);

            // Only the value seen: a request may have renewed the entry since, and removing that
            // lets the next one straight through the cooldown.
            _lastRequested.TryRemove(entry);
        }
    }

    /// <summary>Lets a test renew an entry between the sweep reading it and removing it.</summary>
    internal Action<string>? BeforeSweepRemoves { get; set; }

    // Hashed, so an entry costs the same whatever the caller sent.
    private static string Key(string purpose, string email) =>
        $"{purpose}:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Normalizer.Normalize(email))))}";
}
