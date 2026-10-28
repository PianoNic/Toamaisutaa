namespace Toamaisutaa.Abstractions;

/// <summary>Everything read from the <c>ExternalLogin</c> configuration section.</summary>
/// <remarks>
/// Sign-in through another identity provider that ends in this application's own tokens, as opposed to
/// <c>Oidc:Authority</c>, which accepts that provider's tokens as they are. With no providers configured
/// nothing is mapped.
/// </remarks>
public sealed class ToamaisutaaExternalLoginOptions
{
    /// <summary>
    /// The providers to offer, by key. The key is what the routes, the stored link and the client's
    /// buttons name, so changing one orphans every account linked under it.
    /// </summary>
    public IDictionary<string, ToamaisutaaExternalProviderOptions> Providers { get; set; } =
        new Dictionary<string, ToamaisutaaExternalProviderOptions>(StringComparer.Ordinal);

    /// <summary>
    /// Where a finished sign-in or link may send the browser, compared exactly - scheme, host, port and
    /// path, without the query. Required once a provider is configured. <c>https://</c>, or a custom
    /// scheme such as <c>myapp://auth/callback</c> for a native app; <c>http://</c> only for localhost.
    /// </summary>
    /// <remarks>
    /// Exact rather than by prefix, because whatever is allowed here receives a code that signs somebody
    /// in, and a prefix match is one open redirect away from handing it to someone else.
    /// </remarks>
    public IList<string> AllowedReturnUrls { get; set; } = [];

    /// <summary>
    /// The scheme and host this application is reached on, such as <c>https://api.example.com</c>, used
    /// to build the callback address registered with each provider. Defaults to the request's own, which
    /// is wrong behind a proxy that does not forward the original host and scheme.
    /// </summary>
    public string? CallbackBaseUrl { get; set; }

    /// <summary>How long a begun sign-in stays completable at the provider.</summary>
    public TimeSpan RequestLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long the code handed to the return URL can be exchanged for tokens. Short, because the client
    /// exchanges it the moment it arrives.
    /// </summary>
    public TimeSpan ExchangeCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// How recently an account with neither a password nor a second factor must have signed in to link
    /// another provider. Accounts with either prove that instead.
    /// </summary>
    public TimeSpan LinkProofWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// A relative suffix composed onto <see cref="ToamaisutaaLocalLoginOptions.EndpointPrefix"/>, so
    /// moving local login moves these with it.
    /// </summary>
    public string EndpointPrefix { get; set; } = "/external";
}

/// <summary>One identity provider, found through its discovery document.</summary>
public sealed class ToamaisutaaExternalProviderOptions
{
    /// <summary>What the sign-in button says. Defaults to the key.</summary>
    public string? DisplayName { get; set; }

    /// <summary>An icon for the button, passed to clients as is.</summary>
    public string? IconUrl { get; set; }

    /// <summary>
    /// The issuer, whose <c>/.well-known/openid-configuration</c> names everything else. <c>https://</c>
    /// is required outside Development.
    /// </summary>
    public string? Authority { get; set; }

    public string? ClientId { get; set; }

    /// <summary>
    /// Sent to the token endpoint when set. Leave it unset for a provider that registers this
    /// application as a public client; PKCE is used either way.
    /// </summary>
    public string? ClientSecret { get; set; }

    public IList<string> Scopes { get; set; } = ["openid", "profile", "email"];

    /// <summary>
    /// Off by default. Whether somebody this application has never seen may create an account by
    /// signing in here. Off, only accounts already linked to this provider can use it.
    /// </summary>
    public bool AllowSignUp { get; set; }

    /// <summary>
    /// Off by default. Whether a first sign-in whose address matches an existing account joins that
    /// account, provided the provider says it verified the address.
    /// </summary>
    /// <remarks>
    /// Only turn this on for a provider that really does verify addresses before asserting
    /// <c>email_verified</c>. One that lets users type any address and claims it verified hands over
    /// every account here whose address its users can name. Off, a matching address is refused and the
    /// owner links the provider from a signed-in session instead.
    /// </remarks>
    public bool LinkByVerifiedEmail { get; set; }
}
