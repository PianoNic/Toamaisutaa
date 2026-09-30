using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Keeps the symmetric key as a validation key alongside the asymmetric ones, so tokens in flight
/// survive a move to <c>LocalLogin:SigningKeys</c>.
/// </summary>
/// <remarks>
/// A singleton: the token library caches signature providers per key instance, so these wrappers
/// must be the same objects every time.
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

            if (ReferenceEquals(material, ring.Active))
            {
                // The JWS algorithm names equal the SecurityAlgorithms constants, so this passes straight through.
                Signing = new SigningCredentials(key, material.Algorithm);
            }
        }

        if (Symmetric(options.Value) is { } symmetric)
        {
            _validationKeys.Add(symmetric);
            Signing ??= new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256);
        }
    }

    public SigningCredentials? Signing { get; }

    public IReadOnlyList<SecurityKey> ValidationKeys => _validationKeys;

    public bool Owns(string? keyId) =>
        keyId is not null && _validationKeys.Any(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));

    /// <summary>
    /// A token with no <c>kid</c> gets the whole set, so tokens issued before key ids existed can still
    /// be read.
    /// </summary>
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
    /// Null rather than an exception for a bad key, because the startup check reports it alongside
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
