using System.Security.Cryptography;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class RecoveryCodeHashesTests
{
    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    [Test]
    public async Task A_code_hashed_under_a_key_that_has_since_retired_is_still_found()
    {
        var old = NewKey();
        var before = new ToamaisutaaTwoFactorOptions { EncryptionKey = old };
        var stored = RecoveryCodeHashes.Hash(before, "ABCDEFGHJK");

        var after = new ToamaisutaaTwoFactorOptions
        {
            EncryptionKey = NewKey(),
            EncryptionKeyVersion = "2",
            RetiredEncryptionKeys = { ["1"] = old },
        };

        await Assert.That(RecoveryCodeHashes.Candidates(after, "ABCDEFGHJK").Select(candidate => candidate.Hash)).Contains(stored);
    }

    [Test]
    public async Task The_stored_value_depends_on_the_key()
    {
        var first = RecoveryCodeHashes.Hash(new ToamaisutaaTwoFactorOptions { EncryptionKey = NewKey() }, "ABCDEFGHJK");
        var second = RecoveryCodeHashes.Hash(new ToamaisutaaTwoFactorOptions { EncryptionKey = NewKey() }, "ABCDEFGHJK");

        await Assert.That(first).IsNotEqualTo(second);
        await Assert.That(first).IsNotEqualTo(SecureTokens.HashToken("ABCDEFGHJK"));
    }
}
