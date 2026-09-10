using System.Buffers.Text;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Asymmetric signing on the wire: what the JWKS document says, and which tokens the bearer
/// pipeline accepts once the keys are no longer a shared secret.
/// </summary>
/// <remarks>
/// The keys are generated per test rather than checked in. Every configuration here drops
/// <c>LocalLogin:SigningKey</c> entirely, which is the state a deployment that has finished
/// migrating is in - and the state in which anything still reading only that option stops
/// recognising this package's own tokens.
/// </remarks>
public class JwksHttpTests
{
    private const string Jwks = "/auth/.well-known/jwks.json";

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Asymmetric only: the symmetric key comes out, so nothing can pass by falling back
    /// to it.</summary>
    private static Action<Dictionary<string, string?>> SignedBy(params (string Kid, ECDsa Key)[] keys) => settings =>
    {
        settings.Remove("LocalLogin:SigningKey");

        for (var index = 0; index < keys.Length; index++)
        {
            settings[$"LocalLogin:SigningKeys:{index}:Kid"] = keys[index].Kid;
            settings[$"LocalLogin:SigningKeys:{index}:Pem"] = keys[index].Key.ExportPkcs8PrivateKeyPem();
        }
    };

    /// <summary>
    /// A token for this host signed by a key of the test's choosing. Minted rather than doctored,
    /// for the reason <c>TestApp.MintTokenWithoutSession</c> gives: editing a real token breaks its
    /// signature, so the request never reaches the code under test.
    /// </summary>
    private static string Mint(TestApp app, ECDsa key, string kid, string subject) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "toamaisutaa-tests",
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity([new Claim("sub", subject)]),
            IssuedAt = app.Time.Now.UtcDateTime,
            NotBefore = app.Time.Now.UtcDateTime,
            Expires = app.Time.Now.AddMinutes(15).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(key) { KeyId = kid },
                SecurityAlgorithms.EcdsaSha256),
        });

    /// <summary>The JOSE header of a token, read the way anything downstream reads it.</summary>
    private static JsonElement Header(string token) =>
        JsonDocument.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(token.Split('.')[0]))).RootElement.Clone();

    [Test]
    public async Task Publishes_the_configured_keys_under_the_RFC_7517_names()
    {
        using var key = NewKey();
        await using var app = await TestApp.StartAsync(configure: SignedBy(("2026-09", key)));

        var response = await app.Client.Get(Jwks);
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var published = body.GetProperty("keys");

        await Assert.That(published.GetArrayLength()).IsEqualTo(1);
        await Assert.That(published[0].Names()).IsEquivalentTo(new[] { "kty", "use", "kid", "alg", "crv", "x", "y" });
        await Assert.That(published[0].String("kid")).IsEqualTo("2026-09");
        await Assert.That(published[0].String("alg")).IsEqualTo("ES256");
        await Assert.That(published[0].String("use")).IsEqualTo("sig");

        // Served anonymously to anything that asks, so this is the assertion that matters most.
        await Assert.That(await response.Content.ReadAsStringAsync()).DoesNotContain("\"d\"");
    }

    /// <summary>
    /// A gateway that fetches a JWKS gets a 200 and then refuses every token it sees. Answering an
    /// empty set to an HS256 deployment would make that look like the issuer's fault.
    /// </summary>
    [Test]
    public async Task Is_not_mapped_at_all_when_signing_is_symmetric()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        // Signed in, because the fallback policy answers an unmatched route 401 rather than 404 and
        // that would pass whether the route existed or not.
        var response = await app.Client.Get(Jwks, account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    /// <summary>
    /// The signing half. The <c>kid</c> is what a gateway looks up in the document above, so a
    /// token that does not name one is unvalidatable however correct the key is.
    /// </summary>
    [Test]
    public async Task Signs_with_the_first_key_and_names_it_in_the_header()
    {
        using var current = NewKey();
        using var retired = NewKey();

        await using var app = await TestApp.StartAsync(configure: SignedBy(("2026-09", current), ("2026-03", retired)));

        var account = await Account.RegisterAsync(app);
        var header = Header(account.AccessToken);

        await Assert.That(header.String("alg")).IsEqualTo("ES256");
        await Assert.That(header.String("kid")).IsEqualTo("2026-09");
    }

    /// <summary>
    /// Provisioning recognises its own tokens by the issuer, and used to reach for
    /// <c>LocalLogin:SigningKey</c> to decide whether local login was configured at all. With only
    /// asymmetric keys set that read is empty, and every request would have been provisioned as a
    /// stranger - a new user row per call, on the happy path.
    /// </summary>
    [Test]
    public async Task An_asymmetrically_signed_token_resolves_to_the_user_it_names()
    {
        using var key = NewKey();
        await using var app = await TestApp.StartAsync(configure: SignedBy(("2026-09", key)));

        var account = await Account.RegisterAsync(app);
        var subject = account.Claims().String("sub");

        var first = await (await app.Client.Get("/test/me", account.AccessToken)).Json();
        var second = await (await app.Client.Get("/test/me", account.AccessToken)).Json();

        await Assert.That(first.String("id")).IsEqualTo(subject);
        await Assert.That(second.String("id")).IsEqualTo(subject);
        await Assert.That(first.String("userName")).IsEqualTo("ada");
    }

    /// <summary>Rotation only works if this holds: a key that is no longer first still validates
    /// what it signed, or every session ends the moment a key moves.</summary>
    [Test]
    public async Task Accepts_a_token_signed_by_a_key_that_is_no_longer_first()
    {
        using var current = NewKey();
        using var retired = NewKey();

        await using var app = await TestApp.StartAsync(configure: SignedBy(("2026-09", current), ("2026-03", retired)));

        var account = await Account.RegisterAsync(app);
        var subject = account.Claims().String("sub")!;

        var response = await app.Client.Get("/test/me", Mint(app, retired, "2026-03", subject));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await response.Json()).String("id")).IsEqualTo(subject);
    }

    /// <summary>
    /// Validation goes by <c>kid</c>, and this is the assertion that says so rather than describing
    /// it. The token is signed by the one configured key, so the only thing standing between it and
    /// a 200 is the key id naming nothing - a resolver that handed back the whole set would try
    /// that key anyway and let it through.
    /// </summary>
    [Test]
    public async Task Refuses_a_token_whose_key_id_names_no_configured_key()
    {
        using var key = NewKey();
        await using var app = await TestApp.StartAsync(configure: SignedBy(("2026-09", key)));

        var account = await Account.RegisterAsync(app);
        var subject = account.Claims().String("sub")!;

        var response = await app.Client.Get("/test/me", Mint(app, key, "no-such-key", subject));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// The migration, which is the reason both shapes are read at once. Adding SigningKeys to a
    /// deployment that has been signing HS256 has to leave the tokens already in flight alone -
    /// otherwise switching signs everybody out, and nothing about that failure says why.
    /// </summary>
    [Test]
    public async Task Keeps_validating_HS256_tokens_while_the_symmetric_key_is_still_configured()
    {
        using var key = NewKey();

        await using var app = await TestApp.StartAsync(configure: settings =>
        {
            // LocalLogin:SigningKey is left exactly as the harness sets it.
            settings["LocalLogin:SigningKeys:0:Kid"] = "2026-09";
            settings["LocalLogin:SigningKeys:0:Pem"] = key.ExportPkcs8PrivateKeyPem();
        });

        var account = await Account.RegisterAsync(app);
        var subject = account.Claims().String("sub")!;

        // New tokens are asymmetric from the first sign-in after the switch.
        await Assert.That(Header(account.AccessToken).String("alg")).IsEqualTo("ES256");

        var symmetric = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "toamaisutaa-tests",
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity([new Claim("sub", subject)]),
            IssuedAt = app.Time.Now.UtcDateTime,
            NotBefore = app.Time.Now.UtcDateTime,
            Expires = app.Time.Now.AddMinutes(15).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[32]) { KeyId = Toamaisutaa.Abstractions.ToamaisutaaDefaults.LocalSigningKeyId },
                SecurityAlgorithms.HmacSha256),
        });

        var response = await app.Client.Get("/test/me", symmetric);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await response.Json()).String("id")).IsEqualTo(subject);
    }
}
