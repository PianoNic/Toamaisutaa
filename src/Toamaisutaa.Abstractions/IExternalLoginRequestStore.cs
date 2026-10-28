namespace Toamaisutaa.Abstractions;

/// <summary>Persistence for sign-ins in flight at another identity provider.</summary>
public interface IExternalLoginRequestStore
{
    Task CreateAsync(ToamaisutaaExternalLoginRequest request, CancellationToken cancellationToken = default);

    Task<ToamaisutaaExternalLoginRequest?> FindByStateHashAsync(string stateHash, CancellationToken cancellationToken = default);

    /// <summary>Conditional on it not being spent already. True only for the request that spent it.</summary>
    Task<bool> MarkStateConsumedAsync(Guid requestId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>Records who the provider vouched for, and the code that stands for it until exchanged.</summary>
    Task SetExchangeAsync(
        Guid requestId,
        string exchangeCodeHash,
        Guid userId,
        string securityStamp,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    Task<ToamaisutaaExternalLoginRequest?> FindByExchangeCodeHashAsync(string exchangeCodeHash, CancellationToken cancellationToken = default);

    /// <summary>Conditional on it not being spent already. True only for the request that spent it.</summary>
    Task<bool> MarkExchangeConsumedAsync(Guid requestId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}

/// <summary>
/// One sign-in or link at another identity provider, from the redirect there until the client has
/// exchanged the code it was handed.
/// </summary>
public class ToamaisutaaExternalLoginRequest
{
    public Guid Id { get; set; }

    public string ProviderKey { get; set; } = default!;

    /// <summary>SHA-256 of the <c>state</c> sent to the provider. Unique.</summary>
    public string StateHash { get; set; } = default!;

    /// <summary>Checked against the ID token's <c>nonce</c>, so a token minted for another sign-in is refused.</summary>
    public string Nonce { get; set; } = default!;

    /// <summary>
    /// This application's PKCE verifier toward the provider. Stored as is, because the token endpoint
    /// needs it back; it is worthless without the provider's code, and lives minutes.
    /// </summary>
    public string CodeVerifier { get; set; } = default!;

    /// <summary>The callback address the provider was given, which the token request must repeat exactly.</summary>
    public string RedirectUri { get; set; } = default!;

    public string ReturnUrl { get; set; } = default!;

    /// <summary>Whatever the client passed as <c>state</c>, handed back on the return URL untouched.</summary>
    public string? ClientState { get; set; }

    /// <summary>
    /// The client's PKCE challenge (S256). The exchange code is worth nothing without its verifier, so a
    /// code read off a redirect by another app on the device signs nobody in. Null on a link, which
    /// hands back no code.
    /// </summary>
    public string? ClientCodeChallenge { get; set; }

    /// <summary>Set when a signed-in user is linking this provider, rather than signing in with it.</summary>
    public Guid? LinkUserId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When the redirect to the provider stops being completable, then, once the provider has answered,
    /// when the exchange code does.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set when the provider's answer arrives. A second answer to the same state is refused.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>SHA-256 of the code handed to the return URL. Unique where set.</summary>
    public string? ExchangeCodeHash { get; set; }

    public DateTimeOffset? ExchangeConsumedAt { get; set; }

    /// <summary>Who the provider vouched for.</summary>
    public Guid? UserId { get; set; }

    /// <summary>
    /// The account's stamp when the provider vouched for it. A credential change before the exchange
    /// refuses it, as one during a password sign-in would.
    /// </summary>
    public string? SecurityStamp { get; set; }
}
