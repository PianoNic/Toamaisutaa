namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The version segment, which Argon2's canonical encoding puts between the algorithm and the
/// parameters. Everything else about this format is covered through the hashers that write it.
/// </summary>
public class PhcStringTests
{
    [Test]
    public async Task ReadsTheVersionOutOfItsOwnSegment()
    {
        var parsed = PhcString.TryParse("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g", out var result);

        await Assert.That(parsed).IsTrue();
        await Assert.That(result.Version).IsEqualTo(19);
        await Assert.That(result.Algorithm).IsEqualTo("argon2id");
        await Assert.That(result.TryGetInt32("m", out var memory)).IsTrue();
        await Assert.That(memory).IsEqualTo(19_456);
    }

    /// <summary>A PBKDF2 row has four segments and always did. Reading the parameters out of the
    /// wrong one would break every stored password in a deployment.</summary>
    [Test]
    public async Task StillReadsARowWithNoVersion()
    {
        var parsed = PhcString.TryParse("$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2g", out var result);

        await Assert.That(parsed).IsTrue();
        await Assert.That(result.Version).IsNull();
        await Assert.That(result.TryGetInt32("i", out var iterations)).IsTrue();
        await Assert.That(iterations).IsEqualTo(600_000);
    }

    [Test]
    public async Task RoundTripsAVersion()
    {
        var formatted = PhcString.Format("argon2id", 19, [new KeyValuePair<string, string>("m", "19456")], [1, 2, 3, 4], [5, 6, 7, 8]);

        await Assert.That(formatted).StartsWith("$argon2id$v=19$m=19456$");
        await Assert.That(PhcString.TryParse(formatted, out var result)).IsTrue();
        await Assert.That(result.Version).IsEqualTo(19);
    }

    [Test]
    [Arguments("$argon2id$19$m=19456$c2FsdHNhbHQ$aGFzaGhhc2g")]
    [Arguments("$argon2id$v=$m=19456$c2FsdHNhbHQ$aGFzaGhhc2g")]
    [Arguments("$argon2id$v=nineteen$m=19456$c2FsdHNhbHQ$aGFzaGhhc2g")]
    [Arguments("$argon2id$v=19$m=19456$c2FsdHNhbHQ$aGFzaGhhc2g$extra")]
    public async Task FailsClosedOnAVersionSegmentItCannotRead(string value)
    {
        await Assert.That(PhcString.TryParse(value, out _)).IsFalse();
    }
}
