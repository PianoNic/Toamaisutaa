using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordHashing.Argon2.Tests;

public class Argon2idPasswordHasherTests
{
    // Far below production strength: the OWASP floor is a startup check, not a hasher rule, and
    // these tests run hundreds of derivations.
    private const int TestMemoryKib = 1024;
    private const int TestIterations = 1;
    private const int TestParallelism = 1;

    private const int TestPbkdf2Iterations = 1_000;

    private const string Password = "correct horse battery staple";

    private static readonly string PepperA = Convert.ToBase64String(Enumerable.Range(0, 32).Select(index => (byte)index).ToArray());
    private static readonly string PepperB = Convert.ToBase64String(Enumerable.Range(64, 32).Select(index => (byte)index).ToArray());

    private static Argon2idPasswordHasher Hasher(
        Action<ToamaisutaaArgon2Options>? configure = null,
        Action<ToamaisutaaLocalLoginOptions>? configureLogin = null)
    {
        var argon = new ToamaisutaaArgon2Options
        {
            MemorySizeKib = TestMemoryKib,
            Iterations = TestIterations,
            DegreeOfParallelism = TestParallelism,
        };

        configure?.Invoke(argon);

        return new Argon2idPasswordHasher(Options.Create(argon), Options.Create(Login(configureLogin)), Pbkdf2(configureLogin));
    }

    private static Pbkdf2PasswordHasher Pbkdf2(Action<ToamaisutaaLocalLoginOptions>? configureLogin = null) =>
        new(Options.Create(Login(configureLogin)));

    private static ToamaisutaaLocalLoginOptions Login(Action<ToamaisutaaLocalLoginOptions>? configure)
    {
        var login = new ToamaisutaaLocalLoginOptions { Pbkdf2Iterations = TestPbkdf2Iterations };
        configure?.Invoke(login);

        return login;
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

    [Test]
    public async Task WritesTheStandardArgon2idString()
    {
        var stored = Hasher().Hash(Password);

        await Assert.That(stored).StartsWith($"$argon2id$v=19$m={TestMemoryKib},t={TestIterations},p={TestParallelism}$");
        await Assert.That(stored.Split('$').Length).IsEqualTo(6);
    }

    /// <summary>Derived from Konscious directly rather than from <c>Hash</c>, so the class is not
    /// checked against itself.</summary>
    [Test]
    public async Task VerifiesAHashItDidNotProduce()
    {
        var salt = Encoding.UTF8.GetBytes("0123456789abcdef");
        var derived = Derive(Encoding.UTF8.GetBytes(Password), salt, TestMemoryKib, TestIterations, TestParallelism, 32);

        var stored = $"$argon2id$v=19$m={TestMemoryKib},t={TestIterations},p={TestParallelism}${Encode(salt)}${Encode(derived)}";

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task WhatItWritesIsWhatAnIndependentArgon2idComputes()
    {
        var segments = Hasher().Hash(Password).Split('$');

        var salt = Decode(segments[4]);
        var expected = Derive(Encoding.UTF8.GetBytes(Password), salt, TestMemoryKib, TestIterations, TestParallelism, 32);

        await Assert.That(segments[5]).IsEqualTo(Encode(expected));
    }

    [Test]
    [Arguments("")]
    [Arguments("not-a-phc-string")]
    [Arguments("$argon2id$v=19$m=1024,t=1,p=1$only-five-segments")]
    [Arguments("$argon2id$v=notanumber$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]
    [Arguments("$argon2id$v=19$m=1024,t=1$c2FsdHNhbHQ$aGFzaA")]
    [Arguments("$argon2id$v=19$m=1024,t=0,p=1$c2FsdHNhbHQ$aGFzaA")]
    [Arguments("$argon2id$v=19$m=4,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]
    [Arguments("$argon2id$v=19$m=1024,t=1,p=1$!!!not-base64!!!$aGFzaA")]
    public async Task FailsClosedOnAMalformedRow(string stored)
    {
        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task RefusesAnArgon2VersionItDoesNotImplement()
    {
        var stored = Hasher().Hash(Password).Replace("$v=19$", "$v=16$", StringComparison.Ordinal);

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task RefusesASaltShorterThanRfc9106Allows()
    {
        var salt = Encoding.UTF8.GetBytes("salt");
        var derived = Derive(Encoding.UTF8.GetBytes(Password), salt, TestMemoryKib, TestIterations, TestParallelism, 32);

        var stored = $"$argon2id$v=19$m={TestMemoryKib},t={TestIterations},p={TestParallelism}${Encode(salt)}${Encode(derived)}";

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task AsksForARehashWhenTheStoredMemoryIsWeaker()
    {
        var stored = Hasher().Hash(Password);
        var stronger = Hasher(options => options.MemorySizeKib = TestMemoryKib * 2);

        await Assert.That(stronger.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task AsksForARehashWhenTheStoredIterationsAreWeaker()
    {
        var stored = Hasher().Hash(Password);
        var stronger = Hasher(options => options.Iterations = TestIterations + 1);

        await Assert.That(stronger.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task DoesNotAskForARehashWhenTheParametersMatch()
    {
        var hasher = Hasher();

        await Assert.That(hasher.Verify(Password, hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task DoesNotAskForARehashWhenTheStoredParametersAreStronger()
    {
        var stored = Hasher(options => options.MemorySizeKib = TestMemoryKib * 2).Hash(Password);
        var weaker = Hasher();

        await Assert.That(weaker.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task VerifiesAPbkdf2RowAndAsksForARehash()
    {
        var stored = Pbkdf2().Hash(Password);

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    [Test]
    public async Task RefusesTheWrongPasswordAgainstAPbkdf2Row()
    {
        var stored = Pbkdf2().Hash(Password);

        await Assert.That(Hasher().Verify("not it", stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task APbkdf2RowRehashesToASettledArgon2idRow()
    {
        var hasher = Hasher();
        var stored = Pbkdf2().Hash(Password);

        if (hasher.Verify(Password, stored) != PasswordVerificationResult.SucceededRehashNeeded)
            throw new InvalidOperationException("The PBKDF2 row was not offered for rehashing, so there is nothing to rewrite.");

        var rewritten = hasher.Hash(Password);

        await Assert.That(rewritten).StartsWith("$argon2id$");
        await Assert.That(hasher.Verify(Password, rewritten)).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task VerifyOnlyWritesPbkdf2()
    {
        var stored = Hasher(options => options.VerifyOnly = true).Hash(Password);

        await Assert.That(stored).StartsWith("$pbkdf2-sha256$");
    }

    [Test]
    public async Task VerifyOnlyStillReadsArgon2idRowsAndDrainsThem()
    {
        var stored = Hasher().Hash(Password);
        var draining = Hasher(options => options.VerifyOnly = true);

        await Assert.That(draining.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    /// <summary>A drained row must stop asking for a rehash, or every login rewrites it forever.</summary>
    [Test]
    public async Task VerifyOnlyLeavesAPbkdf2RowAlone()
    {
        var draining = Hasher(options => options.VerifyOnly = true);

        await Assert.That(draining.Verify(Password, Pbkdf2().Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task PepperedHashesNameTheirVersion()
    {
        var stored = Hasher(configureLogin: login => login.Pepper = PepperA).Hash(Password);

        await Assert.That(stored).Contains(",keyid=1$");
    }

    [Test]
    public async Task VerifiesAPepperedHash()
    {
        var hasher = Hasher(configureLogin: login => login.Pepper = PepperA);

        await Assert.That(hasher.Verify(Password, hasher.Hash(Password))).IsEqualTo(PasswordVerificationResult.Succeeded);
    }

    [Test]
    public async Task ADifferentPepperDoesNotVerify()
    {
        var stored = Hasher(configureLogin: login => login.Pepper = PepperA).Hash(Password);
        var other = Hasher(configureLogin: login => login.Pepper = PepperB);

        await Assert.That(other.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task APepperedRowFailsClosedWhenTheKeyIsGone()
    {
        var stored = Hasher(configureLogin: login => login.Pepper = PepperA).Hash(Password);

        await Assert.That(Hasher().Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.Failed);
    }

    [Test]
    public async Task RotatingThePepperVerifiesWithTheOldKeyAndAsksForARehash()
    {
        var stored = Hasher(configureLogin: login => login.Pepper = PepperA).Hash(Password);

        var rotated = Hasher(configureLogin: login =>
        {
            login.Pepper = PepperB;
            login.PepperVersion = "2";
            login.RetiredPeppers["1"] = PepperA;
        });

        await Assert.That(rotated.Verify(Password, stored)).IsEqualTo(PasswordVerificationResult.SucceededRehashNeeded);
    }

    private static byte[] Derive(byte[] password, byte[] salt, int memoryKib, int iterations, int parallelism, int length)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };

        return argon2.GetBytes(length);
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=');

    private static byte[] Decode(string value) =>
        Convert.FromBase64String(value + new string('=', (4 - value.Length % 4) % 4));
}
