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
    AccessToken Issue(ToamaisutaaUser user, IReadOnlyList<string> roles);
}

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);
