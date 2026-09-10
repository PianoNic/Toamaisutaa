using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// The one place configured key material becomes token keys, so a key id means the same thing to
/// the issuer, to the validator and to the JWKS document.
/// </summary>
/// <remarks>
/// <para>
/// Both shapes live here at once on purpose. Adding <c>LocalLogin:SigningKeys</c> to a deployment
/// that has been signing HS256 makes the asymmetric key active immediately while the symmetric one
/// stays a validation key, so the tokens already in flight last out their
/// <c>AccessTokenLifetime</c> instead of being refused by the process that issued them.
/// <c>LocalLogin:SigningKey</c> comes out on the next deploy.
/// </para>
/// <para>
/// A singleton, because <see cref="LocalSigningKeyRing"/> owns the underlying key handles for the
/// life of the application and these wrappers have to be the same objects every time: the token
/// library caches its signature providers per key instance.
/// </para>
/// </remarks>
internal sealed class LocalTokenKeys
{
    private readonly List<SecurityKey> _validationKeys = [];

    public LocalTokenKeys(LocalSigningKeyRing ring, IOptions<ToamaisutaaLocalLoginOptions> options)
    {
        ArgumentNullException.ThrowIfNull(ring);
        ArgumentNullException.ThrowIfNull(options);

        foreach (var material in ring.Keys)
        {
            var key = ToSecurityKey(material);
            _validationKeys.Add(key);

            // Only the first entry signs, which is what makes rotation a matter of putting the new
            // key at the front. The ring answers null when that entry cannot sign, and the startup
            // check has already said so.
            if (ReferenceEquals(material, ring.Active))
            {
                // RS256, ES256, ES384 and ES512 are the JWS names and the SecurityAlgorithms
                // constants alike, so the algorithm the ring read off the key goes straight through.
                Signing = new SigningCredentials(key, material.Algorithm);
            }
        }

        if (Symmetric(options.Value) is { } symmetric)
        {
            _validationKeys.Add(symmetric);
            Signing ??= new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256);
        }
    }

    /// <summary>What signs a locally issued token. Null when nothing is configured, which is the
    /// state a resource server that never issues one is in.</summary>
    public SigningCredentials? Signing { get; }

    /// <summary>Every key a locally issued token may be validated against - the active one, every
    /// retired one, and the symmetric key when it is still configured.</summary>
    public IReadOnlyList<SecurityKey> ValidationKeys => _validationKeys;

    /// <summary>Whether a key id belongs to this package rather than to the identity provider.</summary>
    public bool Owns(string? keyId) =>
        keyId is not null && _validationKeys.Any(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));

    /// <summary>
    /// The keys a token claiming the local issuer may be validated against.
    /// </summary>
    /// <remarks>
    /// Filtered by <c>kid</c> when the token names one, so a token signed by a key this deployment
    /// does not carry is refused rather than tried against every key in turn. A token with no
    /// <c>kid</c> gets the whole set, which is the only way one issued before key ids existed could
    /// still be read.
    /// </remarks>
    public IEnumerable<SecurityKey> Resolve(string? keyId) =>
        string.IsNullOrEmpty(keyId)
            ? _validationKeys
            : _validationKeys.Where(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));

    private static SecurityKey ToSecurityKey(LocalSigningKeyMaterial material) => material.Key switch
    {
        RSA rsa => new RsaSecurityKey(rsa) { KeyId = material.KeyId },
        ECDsa ecdsa => new ECDsaSecurityKey(ecdsa) { KeyId = material.KeyId },
        _ => throw new InvalidOperationException($"The key '{material.KeyId}' is neither RSA nor EC."),
    };

    /// <summary>
    /// <c>LocalLogin:SigningKey</c> as a key, or null when it is absent or unusable. Null rather
    /// than an exception because the startup check is what reports a bad key, in one message with
    /// everything else that is wrong.
    /// </summary>
    private static SymmetricSecurityKey? Symmetric(ToamaisutaaLocalLoginOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SigningKey))
            return null;

        byte[] material;

        try
        {
            material = Convert.FromBase64String(options.SigningKey);
        }
        catch (FormatException)
        {
            return null;
        }

        return material.Length < 32
            ? null
            : new SymmetricSecurityKey(material) { KeyId = ToamaisutaaDefaults.LocalSigningKeyId };
    }
}
