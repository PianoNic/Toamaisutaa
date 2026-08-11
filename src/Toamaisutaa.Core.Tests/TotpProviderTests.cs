using System.Text;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class TotpProviderTests
{
    /// <summary>The RFC 6238 test key: the ASCII string "12345678901234567890".</summary>
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    private static TotpProvider Provider(Action<ToamaisutaaTwoFactorOptions>? configure = null)
    {
        var options = new ToamaisutaaTwoFactorOptions();
        configure?.Invoke(options);

        return new TotpProvider(Options.Create(options));
    }

    /// <summary>
    /// RFC 6238 Appendix B, the SHA-1 rows. Published vectors rather than our own output, so an
    /// implementation that is wrong in a way it agrees with itself about cannot pass.
    /// </summary>
    [Test]
    [Arguments(59L, "94287082")]
    [Arguments(1111111109L, "07081804")]
    [Arguments(1111111111L, "14050471")]
    [Arguments(1234567890L, "89005924")]
    [Arguments(2000000000L, "69279037")]
    [Arguments(20000000000L, "65353130")]
    public async Task Accepts_the_published_RFC_6238_vectors(long unixSeconds, string expected)
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

        // The RFC publishes eight digits. Truncating to six is not a shortcut: the algorithm ends in
        // "modulo ten to the digits", and taking the last six of an eight-digit value is the same
        // arithmetic. So this asserts the full published value, then checks that the six-digit
        // provider - the shape every authenticator app actually uses - agrees with it.
        var eight = TotpCodes.Compute(RfcSecret, at, TimeSpan.FromSeconds(30), 8);
        await Assert.That(eight).IsEqualTo(expected);

        await Assert.That(Provider().TryVerify(RfcSecret, expected[^6..], at, null, out _)).IsTrue();
    }

    [Test]
    public async Task Accepts_a_code_from_the_previous_and_next_step_within_the_drift()
    {
        var provider = Provider(options => options.DriftSteps = 1);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = TimeSpan.FromSeconds(30);

        var previous = TotpCodes.Compute(RfcSecret, now - step, step, 6);
        var next = TotpCodes.Compute(RfcSecret, now + step, step, 6);

        await Assert.That(provider.TryVerify(RfcSecret, previous, now, null, out _)).IsTrue();
        await Assert.That(provider.TryVerify(RfcSecret, next, now, null, out _)).IsTrue();
    }

    [Test]
    public async Task Refuses_a_neighbouring_code_when_the_drift_is_zero()
    {
        var provider = Provider(options => options.DriftSteps = 0);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = TimeSpan.FromSeconds(30);

        var previous = TotpCodes.Compute(RfcSecret, now - step, step, 6);

        await Assert.That(provider.TryVerify(RfcSecret, previous, now, null, out _)).IsFalse();
    }

    /// <summary>
    /// Without this, an observed code stays usable for the rest of its drift window - ninety seconds
    /// at the default - which is long enough for a phishing proxy to replay it.
    /// </summary>
    [Test]
    public async Task Refuses_a_code_from_a_step_already_accepted()
    {
        var provider = Provider();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var code = TotpCodes.Compute(RfcSecret, now, TimeSpan.FromSeconds(30), 6);

        await Assert.That(provider.TryVerify(RfcSecret, code, now, null, out var step)).IsTrue();
        await Assert.That(provider.TryVerify(RfcSecret, code, now, step, out _)).IsFalse();
    }

    [Test]
    public async Task Refuses_anything_that_is_not_the_configured_number_of_digits()
    {
        var provider = Provider();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        await Assert.That(provider.TryVerify(RfcSecret, "12345", now, null, out _)).IsFalse();
        await Assert.That(provider.TryVerify(RfcSecret, "1234567", now, null, out _)).IsFalse();
        await Assert.That(provider.TryVerify(RfcSecret, "abcdef", now, null, out _)).IsFalse();
        await Assert.That(provider.TryVerify(RfcSecret, string.Empty, now, null, out _)).IsFalse();
    }

    [Test]
    public async Task Builds_a_uri_an_authenticator_app_can_read()
    {
        var provider = Provider();
        var uri = provider.BuildUri(RfcSecret, "Toamaisutaa", "pianonic@example.com");

        await Assert.That(uri).StartsWith("otpauth://totp/Toamaisutaa:pianonic%40example.com?secret=");
        await Assert.That(uri).Contains("issuer=Toamaisutaa");
        await Assert.That(uri).Contains("algorithm=SHA1");
        await Assert.That(uri).Contains("digits=6");
        await Assert.That(uri).Contains("period=30");
    }

    [Test]
    public async Task Round_trips_a_secret_through_base32()
    {
        var provider = Provider();
        var encoded = provider.Encode(RfcSecret);

        await Assert.That(encoded).IsEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        await Assert.That(Base32.TryDecode(encoded, out var decoded)).IsTrue();
        await Assert.That(decoded).IsEquivalentTo(RfcSecret);
    }
}
