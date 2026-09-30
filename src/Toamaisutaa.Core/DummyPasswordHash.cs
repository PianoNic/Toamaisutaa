using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Lets a sign-in for an unknown identifier pay for a verification, so response time cannot
/// enumerate accounts. Warmed at startup so the first unknown-user login is not the outlier.
/// </summary>
internal sealed class DummyPasswordHash(IPasswordHasher hasher)
{
    private readonly Lazy<string> _hash = new(
        () => hasher.Hash("toamaisutaa-timing-equalisation-placeholder"),
        LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Burns the same work a real verification would, and discards the answer.</summary>
    internal void Verify(string password) => hasher.Verify(password, _hash.Value);

    internal void Warm() => _ = _hash.Value;
}
