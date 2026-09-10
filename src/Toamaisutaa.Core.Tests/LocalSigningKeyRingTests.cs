using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Reading <c>LocalLogin:SigningKeys</c>, and what gets published from it.
/// </summary>
/// <remarks>
/// The keys are generated here rather than checked in, so nothing in the repository is a key
/// anybody could mistake for one that matters. The published set is asserted off raw JSON for the
/// same reason the HTTP suite is: it is a document other people's software parses, and
/// deserialising it through this package's own record would agree with that record however wrong
/// it was.
/// </remarks>
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

    /// <summary>
    /// The algorithm is read off the key rather than configured, so this is the assertion that the
    /// reading is right. ES512 is the one that catches a careless mapping: its curve is P-521.
    /// </summary>
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

    /// <summary>
    /// The one assertion in this file that is about a secret rather than a shape. This document is
    /// served anonymously to anything that asks, and a private component reaching it hands over the
    /// ability to mint tokens for every user.
    /// </summary>
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

    /// <summary>Rotation, which is the whole reason the option is a list: the new key goes in front
    /// and the old one keeps validating what it signed.</summary>
    [Test]
    public async Task Publishes_every_key_and_signs_with_the_first()
    {
        using var ring = Ring(EcPem("2026-09"), EcPem("2026-03"));

        await Assert.That(ring.Problems).IsEmpty();
        await Assert.That(ring.Active!.KeyId).IsEqualTo("2026-09");
        await Assert.That(PublishedKeys(ring).GetProperty("keys").GetArrayLength()).IsEqualTo(2);
    }

    /// <summary>
    /// A public-only entry is a legitimate thing to configure - it is what a retired key becomes
    /// once the private half is destroyed - so the mistake being caught is putting one first, where
    /// it would be asked to sign.
    /// </summary>
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

    /// <summary>A public-only key further down is not a mistake, and refusing it would make
    /// destroying a retired private half impossible.</summary>
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

    /// <summary>A kid is what picks the key a token is validated against. Two of them make that a
    /// coin toss, and the failing token would be the one signed by whichever lost.</summary>
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

    /// <summary>A JWK names itself, so configuring the kid twice is not required - and a key
    /// exported from a vault arrives with one already set.</summary>
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

    [Test]
    public async Task Refuses_an_RSA_key_below_the_floor()
    {
        using var ring = Ring(RsaPem("small", keySizeBits: 1024));

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Problems.Single()).Contains("1024-bit RSA");
    }

    /// <summary>The symmetric key already carries this id, and two keys answering to one kid is the
    /// ambiguity the duplicate check exists to prevent - it just spans two options here.</summary>
    [Test]
    public async Task Refuses_the_key_id_the_symmetric_key_reserves()
    {
        using var ring = Ring(EcPem(ToamaisutaaDefaults.LocalSigningKeyId));

        await Assert.That(ring.Keys).IsEmpty();
        await Assert.That(ring.Problems.Single()).Contains("reserved");
    }
}
