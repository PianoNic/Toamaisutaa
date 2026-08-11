using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class Pbkdf2PasswordHasherTests
{
    // Well below the configured floor, because these tests run hundreds of derivations and the
    // floor is enforced at startup rather than in the hasher.
    private const int TestIterations = 1_000;

    private const string Password = "correct horse battery staple";

    private static readonly string PepperA = Convert.ToBase64String(Enumerable.Range(0, 32).Select(index => (byte)index).ToArray());
    private static readonly string PepperB = Convert.ToBase64String(Enumerable.Range(64, 32).Select(index => (byte)index).ToArray());

    private static Pbkdf2PasswordHasher Hasher(Action<ToamaisutaaLocalLoginOptions>? configure = null)
    {
        var options = new ToamaisutaaLocalLoginOptions { Pbkdf2Iterations = TestIterations };
        configure?.Invoke(options);

        return new Pbkdf2PasswordHasher(Options.Create(options));
    }

    [Test]
    public async Task VerifiesWhatItHashed()
    {
        var hasher = Hasher();

        await Assert.That(hasher.Verify(Password, hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task RefusesTheWrongPassword()
    {
        var hasher = Hasher();

        await Assert.That(hasher.Verify("not it", hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task EveryHashUsesAFreshSalt()
    {
        var hasher = Hasher();

        await Assert.That(hasher.Hash(Password)).IsNotEqualTo(hasher.Hash(Password));
    }

    /// <summary>
    /// Built from the BCL primitive directly rather than from <c>Hash</c>, so this checks the format
    /// and the derivation wiring against something outside the class instead of against itself.
    /// </summary>
    [Test]
    public async Task VerifiesAHashItDidNotProduce()
    {
        var salt = Encoding.UTF8.GetBytes("0123456789abcdef");
        var derived = Rfc2898DeriveBytes.Pbkdf2(Password, salt, TestIterations, HashAlgorithmName.SHA256, 32);

        var stored = $"$pbkdf2-sha256$i={TestIterations}${Convert.ToBase64String(salt).TrimEnd('=')}${Convert.ToBase64String(derived).TrimEnd('=')}";

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    [Arguments("")]
    [Arguments("not-a-phc-string")]
    [Arguments("$pbkdf2-sha256$i=1000$only-three-segments")]
    [Arguments("$pbkdf2-sha256$$c2FsdA$aGFzaA")]
    [Arguments("$pbkdf2-sha256$i=notanumber$c2FsdA$aGFzaA")]
    [Arguments("$pbkdf2-sha256$i=0$c2FsdA$aGFzaA")]
    [Arguments("$pbkdf2-sha256$i=1000$!!!not-base64!!!$aGFzaA")]
    public async Task FailsClosedOnAMalformedRow(string stored)
    {
        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    // A row an Argon2 hasher wrote is not ours to check. Accepting whatever we can parse would be
    // the dangerous alternative.
    [Test]
    public async Task RefusesAnAlgorithmItDoesNotImplement()
    {
        const string argon2 = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g";

        await Assert.That(Hasher().Verify(Password, argon2)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task AsksForARehashWhenTheStoredIterationsAreWeaker()
    {
        var stored = Hasher(options => options.Pbkdf2Iterations = TestIterations).Hash(Password);
        var stronger = Hasher(options => options.Pbkdf2Iterations = TestIterations * 2);

        await Assert.That(stronger.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task DoesNotAskForARehashWhenTheParametersMatch()
    {
        var hasher = Hasher();

        await Assert.That(hasher.Verify(Password, hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task DoesNotAskForARehashWhenTheStoredIterationsAreStronger()
    {
        var stored = Hasher(options => options.Pbkdf2Iterations = TestIterations * 2).Hash(Password);
        var weaker = Hasher(options => options.Pbkdf2Iterations = TestIterations);

        await Assert.That(weaker.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    // ── Pepper ──

    [Test]
    public async Task PepperedHashesNameTheirVersion()
    {
        var stored = Hasher(options => options.Pepper = PepperA).Hash(Password);

        await Assert.That(stored).StartsWith("$pbkdf2-sha256-p1$");
    }

    [Test]
    public async Task VerifiesAPepperedHash()
    {
        var hasher = Hasher(options => options.Pepper = PepperA);

        await Assert.That(hasher.Verify(Password, hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    // The whole point of a pepper: the stored row plus the password is not enough without the key.
    [Test]
    public async Task ADifferentPepperDoesNotVerify()
    {
        var stored = Hasher(options => options.Pepper = PepperA).Hash(Password);
        var other = Hasher(options => options.Pepper = PepperB);

        await Assert.That(other.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task APepperedRowFailsClosedWhenTheKeyIsGone()
    {
        var stored = Hasher(options => options.Pepper = PepperA).Hash(Password);

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task IntroducingAPepperRehashesExistingRows()
    {
        var stored = Hasher().Hash(Password);
        var peppered = Hasher(options => options.Pepper = PepperA);

        await Assert.That(peppered.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task RemovingThePepperRehashesRowsThatStillHaveOne()
    {
        var stored = Hasher(options => options.Pepper = PepperA).Hash(Password);

        // The retired key is still held, so the row verifies - and is rewritten without one.
        var plain = Hasher(options => options.RetiredPeppers["1"] = PepperA);

        await Assert.That(plain.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task RotatingThePepperVerifiesWithTheOldKeyAndAsksForARehash()
    {
        var stored = Hasher(options => options.Pepper = PepperA).Hash(Password);

        var rotated = Hasher(options =>
        {
            options.Pepper = PepperB;
            options.PepperVersion = "2";
            options.RetiredPeppers["1"] = PepperA;
        });

        await Assert.That(rotated.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task ARehashAfterRotationCarriesTheNewVersion()
    {
        var rotated = Hasher(options =>
        {
            options.Pepper = PepperB;
            options.PepperVersion = "2";
            options.RetiredPeppers["1"] = PepperA;
        });

        var rewritten = rotated.Hash(Password);

        await Assert.That(rewritten).StartsWith("$pbkdf2-sha256-p2$");
        await Assert.That(rotated.Verify(Password, rewritten)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }
}
