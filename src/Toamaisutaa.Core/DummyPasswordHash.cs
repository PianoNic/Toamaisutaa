using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// One throwaway hash, computed once, so a sign-in attempt against an identifier that does not
/// exist can still pay for a verification.
/// </summary>
/// <remarks>
/// Without this, the response time answers a question the response body refuses to: a request for
/// an unknown user returns in microseconds while a request for a real one spends a key derivation,
/// and anyone can enumerate accounts with a stopwatch. The startup check forces this to be computed
/// before the first request, so the very first unknown-user login is not itself the outlier.
/// </remarks>
internal sealed class DummyPasswordHash(IPasswordHasher hasher)
{
    private readonly Lazy<string> _hash = new(
        () => hasher.Hash("toamaisutaa-timing-equalisation-placeholder"),
        LazyThreadSafetyMode.ExecutionAndPublication);

    internal string Value => _hash.Value;

    /// <summary>Burns the same work a real verification would, and discards the answer.</summary>
    internal void Verify(string password) => hasher.Verify(password, Value);

    internal void Warm() => _ = _hash.Value;
}
