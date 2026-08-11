namespace Toamaisutaa.Abstractions;

/// <summary>
/// What the SPA needs to start an authorization-code flow, served at runtime so the frontend build
/// stays environment-agnostic.
/// </summary>
public sealed record ToamaisutaaClientConfiguration
{
    public required string Authority { get; init; }

    public required string ClientId { get; init; }

    public required string RedirectUri { get; init; }

    public required string PostLogoutRedirectUri { get; init; }

    public required string Scope { get; init; }
}
