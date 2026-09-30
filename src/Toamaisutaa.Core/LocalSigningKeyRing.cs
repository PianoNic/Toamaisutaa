using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class LocalSigningKeyMaterial(string keyId, string algorithm, AsymmetricAlgorithm key, bool canSign) : IDisposable
{
    public string KeyId { get; } = keyId;

    /// <summary>
    /// Read off the key rather than configured, so a curve and algorithm can never contradict.
    /// </summary>
    public string Algorithm { get; } = algorithm;

    public AsymmetricAlgorithm Key { get; } = key;

    public bool CanSign { get; } = canSign;

    public void Dispose() => Key.Dispose();
}

/// <summary>
/// Never throws: a bad entry becomes a line in <see cref="Problems"/> for the startup checks to
/// report together, since a first exception would hide the rest.
/// </summary>
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

    public IReadOnlyList<LocalSigningKeyMaterial> Keys => _keys;

    public LocalSigningKeyMaterial? Active => _keys.Count > 0 && _keys[0].CanSign ? _keys[0] : null;

    public IReadOnlyList<string> Problems => _problems;

    public bool HasPublicKeys => _keys.Count > 0;

    /// <summary>
    /// Built from a public-only export, so a private component cannot reach the JWKS document.
    /// </summary>
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
                $"{label} is an EC key on the curve '{CurveName(key)}', which no JWS algorithm names. Use P-256, "
                + "P-384 or P-521, or an RSA key.");
            key.Dispose();
            return;
        }

        _keys.Add(new LocalSigningKeyMaterial(keyId, algorithm, key, CanSign(key)));
    }

    private AsymmetricAlgorithm? FromPem(string pem, string label)
    {
        // A PKCS#8 "PRIVATE KEY" header does not say whether it holds RSA or EC, so both are tried.
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

            // .NET builds an RSA private key from the CRT parameters, not from d alone.
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
        // One-to-one only because Algorithm refuses keys off these three curves. ES512 is P-521.
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
        ECDsa ecdsa => EcAlgorithm(ecdsa),
        _ => null,
    };

    /// <summary>
    /// Read off the curve, not the key size: secp256k1 is also 256 bits and would otherwise be
    /// published as ES256 under <c>"crv": "P-256"</c>.
    /// </summary>
    private static string? EcAlgorithm(ECDsa key) => Curve(key)?.Oid?.Value switch
    {
        "1.2.840.10045.3.1.7" => "ES256",
        "1.3.132.0.34" => "ES384",
        "1.3.132.0.35" => "ES512",
        _ => null,
    };

    private static ECCurve? Curve(ECDsa key)
    {
        try
        {
            return key.ExportParameters(includePrivateParameters: false).Curve;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static string CurveName(AsymmetricAlgorithm key) =>
        key is ECDsa ecdsa && Curve(ecdsa)?.Oid is { } oid
            ? oid.FriendlyName ?? oid.Value ?? "(unnamed)"
            : "(unreadable)";

    /// <summary>
    /// Asked by exporting, because public and private imports are the same type.
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
            // ImportFromPem throws this when the text carries no PEM at all.
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
