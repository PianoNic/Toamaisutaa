using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class EmailVerificationCodeTests
{
    private static EmailVerificationCodeHashes Hashes(string signingKey)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new ToamaisutaaLocalLoginOptions { SigningKey = signingKey });
        return new EmailVerificationCodeHashes(options, new LocalSigningKeyRing(options));
    }

    private static readonly string Key = Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());

    [Test]
    public async Task A_stored_hash_matches_its_own_code_and_user_only()
    {
        var hashes = Hashes(Key);
        var user = Guid.NewGuid();
        var stored = hashes.Hash(user, "123456");

        await Assert.That(hashes.Matches(stored, user, "123456")).IsTrue();
        await Assert.That(hashes.Matches(stored, user, "123457")).IsFalse();
        await Assert.That(hashes.Matches(stored, Guid.NewGuid(), "123456")).IsFalse();
    }

    /// <summary>A plain hash of six digits is reversed by trying all million of them.</summary>
    [Test]
    public async Task The_hash_is_keyed()
    {
        var user = Guid.NewGuid();
        var other = Convert.ToBase64String(new byte[32]);

        await Assert.That(Hashes(Key).Hash(user, "123456")).IsNotEqualTo(Hashes(other).Hash(user, "123456"));
        await Assert.That(Hashes(Key).Hash(user, "123456")).IsNotEqualTo(SecureTokens.HashToken("123456"));
    }

    [Test]
    [Arguments("ada@example.com", "a***@example.com")]
    [Arguments("a@example.com", "a***@example.com")]
    [Arguments("not-an-address", "***")]
    public async Task The_address_is_masked_for_the_challenge(string email, string masked) =>
        await Assert.That(EmailVerificationGate.Mask(email)).IsEqualTo(masked);
}
