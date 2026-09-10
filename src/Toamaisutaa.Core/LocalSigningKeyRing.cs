using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// One entry of <c>LocalLogin:SigningKeys</c> after parsing: the key id a token carries in its
/// <c>kid</c> header, the JWS algorithm the key implies, and the key itself.
/// </summary>
internal sealed class LocalSigningKeyMaterial(string keyId, string algorithm, AsymmetricAlgorithm key, bool canSign) : IDisposable
{
    public string KeyId { get; } = keyId;

    /// <summary>
    /// <c>RS256</c>, <c>ES256</c>, <c>ES384</c> or <c>ES512</c>. Read off the key rather than
    /// configured: a curve and an algorithm naming a different one is a contradiction with no
    /// sensible resolution, and the key is the half that cannot be wrong.
    /// </summary>
    public string Algorithm { get; } = algorithm;

    public AsymmetricAlgorithm Key { get; } = key;

    /// <summary>False for an entry carrying only a public half, which is all a retired key needs in
    /// order to keep validating the tokens it signed.</summary>
    public bool CanSign { get; } = canSign;

    public void Dispose() => Key.Dispose();
}

/// <summary>
/// Reads <c>LocalLogin:SigningKeys</c> once, at construction, and owns the resulting keys for the
/// life of the application.
/// </summary>
/// <remarks>
/// <para>
/// A singleton because importing a PEM allocates a key handle and the signing path runs on every
/// sign-in; the alternative was importing the same key again per token.
/// </para>
/// <para>
/// It never throws. A bad entry becomes a line in <see cref="Problems"/>, which
/// <see cref="PasswordLoginStartupCheck"/> reports next to every other misconfiguration in one
/// message - a first exception would hide the rest, and a key list is exactly where two mistakes at
/// once is normal.
/// </para>
/// </remarks>
internal sealed class LocalSigningKeyRing : IDisposable
{
    private const int MinimumRsaKeySizeBits = 2048;

    private readonly List<LocalSigningKeyMaterial> _keys = [];
    private readonly List<string> _problems = [];

    public LocalSigningKeyRing(IOptions<ToamaisutaaLocalLoginOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = options.Value;

        for (var index = 0; index < settings.SigningKeys.Count; index++)
            Read(settings.SigningKeys[index], index);

        foreach (var duplicate in _keys.GroupBy(key => key.KeyId, StringComparer.Ordinal).Where(group => group.Count() > 1))
        {
            _problems.Add(
                $"LocalLogin:SigningKeys carries the kid '{duplicate.Key}' more than once. A kid is how a validator "
                + "picks the key a token was signed with, so two of them make that ambiguous.");
        }

        if (_keys.Count > 0 && !_keys[0].CanSign)
        {
            _problems.Add(
                "The first entry of LocalLogin:SigningKeys carries only a public key. The first entry is the active "
                + "one and has to be able to sign; a public-only key belongs further down the list, where it keeps "
                + "validating the tokens it signed.");
        }
    }

    /// <summary>Every configured key, in configuration order, and every one of them validates.</summary>
    public IReadOnlyList<LocalSigningKeyMaterial> Keys => _keys;

    /// <summary>The key that signs, which is the first entry. Null when none is configured, or when
    /// the first entry cannot sign - in which case <see cref="Problems"/> says so.</summary>
    public LocalSigningKeyMaterial? Active => _keys.Count > 0 && _keys[0].CanSign ? _keys[0] : null;

    /// <summary>What is wrong with the configured list, in the words the startup check prints.</summary>
    public IReadOnlyList<string> Problems => _problems;

    /// <summary>Whether there is anything to publish at all. False for a deployment signing HS256,
    /// where the JWKS endpoint is not mapped.</summary>
    public bool HasPublicKeys => _keys.Count > 0;

    /// <summary>
    /// The public halves, as the document the JWKS endpoint serves.
    /// </summary>
    /// <remarks>
    /// Built from an export that asks for public parameters only, so a private component cannot
    /// reach the document even if a future edit here is careless about which field it copies.
    /// </remarks>
    public JsonWebKeySetResponse PublicKeys() => new() { Keys = [.. _keys.Select(PublicKey)] };

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    private void Read(ToamaisutaaSigningKeyOptions? entry, int index)
    {
        var label = $"LocalLogin:SigningKeys[{index}]";

        if (entry is null)
        {
            _problems.Add($"{label} is empty.");
            return;
        }

        var hasPem = !string.IsNullOrWhiteSpace(entry.Pem);
        var hasJwk = !string.IsNullOrWhiteSpace(entry.Jwk);

        if (hasPem == hasJwk)
        {
            _problems.Add($"{label} must set exactly one of Pem and Jwk.");
            return;
        }

        var keyId = string.IsNullOrWhiteSpace(entry.Kid) ? null : entry.Kid;
        var key = hasPem ? FromPem(entry.Pem!, label) : FromJwk(entry.Jwk!, label, ref keyId);

        if (key is null)
            return;

        if (string.IsNullOrWhiteSpace(keyId))
        {
            _problems.Add(
                $"{label} has no Kid. A key id is what a token carries in its header and what a validator uses to "
                + "find this key again, so it cannot be left out.");
            key.Dispose();
            return;
        }

        if (string.Equals(keyId, ToamaisutaaDefaults.LocalSigningKeyId, StringComparison.Ordinal))
        {
            _problems.Add(
                $"{label} uses the kid '{ToamaisutaaDefaults.LocalSigningKeyId}', which is reserved for the symmetric "
                + "LocalLogin:SigningKey.");
            key.Dispose();
            return;
        }

        if (key is RSA rsa && rsa.KeySize < MinimumRsaKeySizeBits)
        {
            _problems.Add($"{label} is a {rsa.KeySize}-bit RSA key; {MinimumRsaKeySizeBits} is the floor.");
            key.Dispose();
            return;
        }

        if (Algorithm(key) is not { } algorithm)
        {
            _problems.Add(
                $"{label} is an EC key on a curve no JWS algorithm names. Use P-256, P-384 or P-521, or an RSA key.");
            key.Dispose();
            return;
        }

        _keys.Add(new LocalSigningKeyMaterial(keyId, algorithm, key, CanSign(key)));
    }

    private AsymmetricAlgorithm? FromPem(string pem, string label)
    {
        // Both are tried because a PKCS#8 "PRIVATE KEY" header says nothing about what is inside it,
        // so the only way to tell an RSA key from an EC one is to import it.
        var rsa = RSA.Create();

        if (TryImport(() => rsa.ImportFromPem(pem)))
            return rsa;

        rsa.Dispose();

        var ecdsa = ECDsa.Create();

        if (TryImport(() => ecdsa.ImportFromPem(pem)))
            return ecdsa;

        ecdsa.Dispose();

        _problems.Add($"{label}:Pem is not a PEM-encoded RSA or EC key.");
        return null;
    }

    private AsymmetricAlgorithm? FromJwk(string json, string label, ref string? keyId)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            _problems.Add($"{label}:Jwk is not valid JSON. It is one JSON Web Key, not a set.");
            return null;
        }

        using (document)
        {
            var jwk = document.RootElement;

            if (jwk.ValueKind != JsonValueKind.Object)
            {
                _problems.Add($"{label}:Jwk is not a JSON object. It is one JSON Web Key, not a set.");
                return null;
            }

            // A JWK carries its own key id, so Kid only has to be configured when the key does not
            // name itself.
            keyId ??= Text(jwk, "kid");

            return Text(jwk, "kty") switch
            {
                "RSA" => RsaFromJwk(jwk, label),
                "EC" => EcFromJwk(jwk, label),
                var kty => Unsupported(label, kty),
            };
        }
    }

    private AsymmetricAlgorithm? Unsupported(string label, string? keyType)
    {
        _problems.Add(
            $"{label}:Jwk has kty '{keyType ?? "(missing)"}'. Only RSA and EC keys sign a JWT here.");

        return null;
    }

    private AsymmetricAlgorithm? RsaFromJwk(JsonElement jwk, string label)
    {
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlBytes(jwk, "n"),
            Exponent = Base64UrlBytes(jwk, "e"),
        };

        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            _problems.Add($"{label}:Jwk is an RSA key without a readable n and e.");
            return null;
        }

        if (jwk.TryGetProperty("d", out _))
        {
            parameters.D = Base64UrlBytes(jwk, "d");
            parameters.P = Base64UrlBytes(jwk, "p");
            parameters.Q = Base64UrlBytes(jwk, "q");
            parameters.DP = Base64UrlBytes(jwk, "dp");
            parameters.DQ = Base64UrlBytes(jwk, "dq");
            parameters.InverseQ = Base64UrlBytes(jwk, "qi");

            // .NET builds an RSA private key from the CRT parameters, not from d alone. Every JWK
            // generator emits them; a key missing them was hand-assembled and is worth saying so.
            if (parameters.P is null || parameters.Q is null || parameters.DP is null
                || parameters.DQ is null || parameters.InverseQ is null)
            {
                _problems.Add($"{label}:Jwk is a private RSA key but is missing p, q, dp, dq or qi.");
                return null;
            }
        }

        var rsa = RSA.Create();

        if (TryImport(() => rsa.ImportParameters(parameters)))
            return rsa;

        rsa.Dispose();
        _problems.Add($"{label}:Jwk is an RSA key whose parameters do not form a key.");
        return null;
    }

    private AsymmetricAlgorithm? EcFromJwk(JsonElement jwk, string label)
    {
        var curveName = Text(jwk, "crv");

        var curve = curveName switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => default(ECCurve?),
        };

        if (curve is null)
        {
            _problems.Add($"{label}:Jwk has crv '{curveName ?? "(missing)"}'. Use P-256, P-384 or P-521.");
            return null;
        }

        var x = Base64UrlBytes(jwk, "x");
        var y = Base64UrlBytes(jwk, "y");

        if (x is null || y is null)
        {
            _problems.Add($"{label}:Jwk is an EC key without a readable x and y.");
            return null;
        }

        var parameters = new ECParameters
        {
            Curve = curve.Value,
            Q = new ECPoint { X = x, Y = y },
            D = Base64UrlBytes(jwk, "d"),
        };

        var ecdsa = ECDsa.Create();

        if (TryImport(() => ecdsa.ImportParameters(parameters)))
            return ecdsa;

        ecdsa.Dispose();
        _problems.Add($"{label}:Jwk is an EC key whose parameters do not form a key.");
        return null;
    }

    private static JsonWebKeyResponse PublicKey(LocalSigningKeyMaterial material) => material.Key switch
    {
        RSA rsa => RsaJwk(material, rsa.ExportParameters(includePrivateParameters: false)),
        ECDsa ecdsa => EcJwk(material, ecdsa.ExportParameters(includePrivateParameters: false)),
        _ => throw new InvalidOperationException($"The key '{material.KeyId}' is neither RSA nor EC."),
    };

    private static JsonWebKeyResponse RsaJwk(LocalSigningKeyMaterial material, RSAParameters parameters) => new()
    {
        KeyType = "RSA",
        KeyId = material.KeyId,
        Algorithm = material.Algorithm,
        Modulus = Base64Url.EncodeToString(parameters.Modulus ?? []),
        Exponent = Base64Url.EncodeToString(parameters.Exponent ?? []),
    };

    private static JsonWebKeyResponse EcJwk(LocalSigningKeyMaterial material, ECParameters parameters) => new()
    {
        KeyType = "EC",
        KeyId = material.KeyId,
        Algorithm = material.Algorithm,
        // Named off the algorithm rather than the exported curve, because a named curve exports as
        // an OID and the two are one-to-one here. ES512 is P-521, which is why this is a map and
        // not string arithmetic on the algorithm name.
        Curve = material.Algorithm switch
        {
            "ES256" => "P-256",
            "ES384" => "P-384",
            _ => "P-521",
        },
        X = Base64Url.EncodeToString(parameters.Q.X ?? []),
        Y = Base64Url.EncodeToString(parameters.Q.Y ?? []),
    };

    private static string? Algorithm(AsymmetricAlgorithm key) => key switch
    {
        RSA => "RS256",
        ECDsa { KeySize: 256 } => "ES256",
        ECDsa { KeySize: 384 } => "ES384",
        ECDsa { KeySize: 521 } => "ES512",
        _ => null,
    };

    /// <summary>
    /// Whether the entry holds a private half. Asked by exporting it, because there is no other way
    /// to tell: a key imported from a public PEM and one imported from a private PEM are the same
    /// type, and the difference only shows when something tries to sign.
    /// </summary>
    private static bool CanSign(AsymmetricAlgorithm key)
    {
        try
        {
            switch (key)
            {
                case RSA rsa:
                    rsa.ExportParameters(includePrivateParameters: true);
                    return true;
                case ECDsa ecdsa:
                    ecdsa.ExportParameters(includePrivateParameters: true);
                    return true;
                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryImport(Action import)
    {
        try
        {
            import();
            return true;
        }
        catch (ArgumentException)
        {
            // What ImportFromPem throws when the text carries no PEM at all.
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static byte[]? Base64UrlBytes(JsonElement element, string name)
    {
        if (Text(element, name) is not { Length: > 0 } value)
            return null;

        try
        {
            return Base64Url.DecodeFromChars(value);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
