using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The published set is asserted off raw JSON because deserialising it through the package's own
/// record would agree with that record however wrong it was.
/// </summary>
public class LocalSigningKeyRingTests
{
    private static LocalSigningKeyRing Ring(params ToamaisutaaSigningKeyOptions[] keys) =>
        new(Options.Create(new ToamaisutaaLocalLoginOptions { SigningKeys = keys }));

    private static ToamaisutaaSigningKeyOptions EcPem(string kid)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new ToamaisutaaSigningKeyOptions { Kid = kid, Pem = key.ExportPkcs8PrivateKeyPem() };
    }

    private static ToamaisutaaSigningKeyOptions RsaPem(string kid, int keySizeBits = 2048)
    {
        using var key = RSA.Create(keySizeBits);
        return new ToamaisutaaSigningKeyOptions { Kid = kid, Pem = key.ExportPkcs8PrivateKeyPem() };
    }

    private static JsonElement PublishedKeys(LocalSigningKeyRing ring) =>
        JsonDocument.Parse(JsonSerializer.Serialize(ring.PublicKeys())).RootElement.Clone();

    /// <summary>ES512 is the one that catches a careless mapping: its curve is P-521.</summary>
    [Test]
    public async Task Names_the_algorithm_the_key_implies()
    {
        using var p521 = ECDsa.Create(ECCurve.NamedCurves.nistP521);

        using var ring = Ring(
            EcPem("ec"),
            new ToamaisutaaSigningKeyOptions { Kid = "ec-521", Pem = p521.ExportPkcs8PrivateKeyPem() },
            RsaPem("rsa"));

        await Assert.That(ring.Problems).IsEmpty();
        await Assert.That(ring.Keys.Select(key => key.Algorithm)).IsEquivalentTo(new[] { "ES256", "ES512", "RS256" });

        var published = PublishedKeys(ring).GetProperty("keys");

        await Assert.That(published[1].GetProperty("crv").GetString()).IsEqualTo("P-521");
    }

    [Test]
    public async Task Publishes_public_material_and_nothing_else()
    {
        using var ring = Ring(RsaPem("rsa"), EcPem("ec"));

        var json = JsonSerializer.Serialize(ring.PublicKeys());
        var published = JsonDocument.Parse(json).RootElement.GetProperty("keys");

        await Assert.That(published[0].EnumerateObject().Select(property => property.Name))
            .IsEquivalentTo(new[] { "kty", "use", "kid", "alg", "n", "e" });

        await Assert.That(published[1].EnumerateObject().Select(property => property.Name))
            .IsEquivalentTo(new[] { "kty", "use", "kid", "alg", "crv", "x", "y" });

        foreach (var privateComponent in new[] { "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"" })
            await Assert.That(json).DoesNotContain(privateComponent);
    }

    [Test]
    public async Task Publishes_every_key_and_signs_with_the_first()
    {
        using var ring = Ring(EcPem("2026-09"), EcPem("2026-03"));

        await Assert.That(ring.Problems).IsEmpty();
        await Assert.That(ring.Active!.KeyId).IsEqualTo("2026-09");
        await Assert.That(PublishedKeys(ring).GetProperty("keys").GetArrayLength()).IsEqualTo(2);
    }

    [Test]
    public async Task Refuses_a_public_only_key_in_the_active_position()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var ring = Ring(
            new ToamaisutaaSigningKeyOptions { Kid = "public-only", Pem = key.ExportSubjectPublicKeyInfoPem() },
            EcPem("private"));

        await Assert.That(ring.Active).IsNull();
        await Assert.That(ring.Problems.Single()).Contains("only a public key");
    }

    [Test]
    public async Task Accepts_a_public_only_key_behind_the_active_one()
    {
        using var retired = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var ring = Ring(
            EcPem("current"),
            new ToamaisutaaSigningKeyOptions { Kid = "retired", Pem = retired.ExportSubjectPublicKeyInfoPem() });

        await Assert.That(ring.Problems).IsEmpty();
        await Assert.That(ring.Active!.KeyId).IsEqualTo("current");
        await Assert.That(ring.Keys[1].CanSign).IsFalse();
    }

    [Test]
    public async Task Refuses_a_repeated_key_id()
    {
        using var ring = Ring(EcPem("same"), EcPem("same"));

        await Assert.That(ring.Problems.Single()).Contains("more than once");
    }

    [Test]
    public async Task Refuses_an_entry_with_no_key_id()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var ring = Ring(new ToamaisutaaSigningKeyOptions { Pem = key.ExportPkcs8PrivateKeyPem() });

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Problems.Single()).Contains("has no Kid");
    }

    [Test]
    public async Task Reads_a_JWK_and_takes_the_key_id_from_it()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(includePrivateParameters: true);

        var jwk = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["kid"] = "from-the-key",
            ["x"] = System.Buffers.Text.Base64Url.EncodeToString(parameters.Q.X!),
            ["y"] = System.Buffers.Text.Base64Url.EncodeToString(parameters.Q.Y!),
            ["d"] = System.Buffers.Text.Base64Url.EncodeToString(parameters.D!),
        });

        using var ring = Ring(new ToamaisutaaSigningKeyOptions { Jwk = jwk });

        await Assert.That(ring.Problems).IsEmpty();
        await Assert.That(ring.Active!.KeyId).IsEqualTo("from-the-key");
        await Assert.That(ring.Active.Algorithm).IsEqualTo("ES256");
    }

    /// <summary>
    /// secp256k1 is 256 bits and imports from a PEM as readily as P-256, so a ring reading the
    /// algorithm off the key size alone would publish it as ES256 under <c>crv: P-256</c>.
    /// </summary>
    [Test]
    public async Task Refuses_an_EC_key_on_a_curve_no_JWS_algorithm_names()
    {
        using var key = ECDsa.Create(ECCurve.CreateFromValue("1.3.132.0.10"));

        using var ring = Ring(new ToamaisutaaSigningKeyOptions { Kid = "k1", Pem = key.ExportPkcs8PrivateKeyPem() });

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Active).IsNull();
        await Assert.That(ring.Problems.Single()).Contains("no JWS algorithm names");

        // The platform's crypto backend decides whether it is spelled secP256k1 or secp256k1.
        await Assert.That(ring.Problems.Single()).Contains("256k1");
    }

    [Test]
    public async Task Refuses_an_RSA_key_below_the_floor()
    {
        using var ring = Ring(RsaPem("small", keySizeBits: 1024));

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Problems.Single()).Contains("1024-bit RSA");
    }

    [Test]
    public async Task Refuses_the_key_id_the_symmetric_key_reserves()
    {
        using var ring = Ring(EcPem(ToamaisutaaDefaults.LocalSigningKeyId));

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Problems.Single()).Contains("reserved");
    }
}
