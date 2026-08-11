namespace Toamaisutaa.Abstractions;

/// <summary>
/// Mints the short-lived access token a successful local sign-in returns. Implemented outside
/// <c>Core</c>, because signing a JWT needs a JWT library and Core carries no third-party packages.
/// </summary>
public interface IAccessTokenIssuer
{
    /// <summary>
    /// The resulting token must be indistinguishable downstream from one the identity provider
    /// issued: same claim shape, validated by the same pipeline, understood by the same policies.
    /// </summary>
    /// <remarks>
    /// Asynchronous even though the shipped implementation signs in memory and never waits for
    /// anything. Signing is exactly the operation that later moves to a key management service or an
    /// HSM, and by then this is a published interface that cannot change shape.
    /// </remarks>
    Task<AccessToken> IssueAsync(
        ToamaisutaaUser user,
        IReadOnlyList<string> roles,
        CancellationToken cancellationToken = default);
}

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);
