using Microsoft.Extensions.Options;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

public class HibpStartupCheckTests
{
    private static HibpStartupCheck Check(Action<ToamaisutaaHibpOptions>? configure = null)
    {
        var options = new ToamaisutaaHibpOptions();
        configure?.Invoke(options);

        return new HibpStartupCheck(Options.Create(options));
    }

    [Test]
    public async Task TheDefaultsStartCleanly()
    {
        await Check().StartAsync(CancellationToken.None);
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    public async Task RefusesToStartWithAThresholdBelowOne(int threshold)
    {
        await Assert.That(() => Check(options => options.BreachThreshold = threshold).StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("")]
    [Arguments("pwned.example.com")]
    [Arguments("/range")]
    public async Task RefusesToStartWithABaseAddressThatIsNotAnAbsoluteUri(string address)
    {
        await Assert.That(() => Check(options => options.ApiBaseAddress = address).StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("file:///srv/pwned/")]
    [Arguments("ftp://mirror.internal/pwned/")]
    public async Task RefusesToStartWithABaseAddressThatIsNotHttp(string address)
    {
        await Assert.That(() => Check(options => options.ApiBaseAddress = address).StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task StartsWithAMirrorAddressThatHasNoTrailingSlash()
    {
        await Check(options => options.ApiBaseAddress = "https://mirror.internal/pwned").StartAsync(CancellationToken.None);
    }

    [Test]
    public async Task RefusesToStartWithATimeoutOfZero()
    {
        await Assert.That(() => Check(options => options.Timeout = TimeSpan.Zero).StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWithNoUserAgent()
    {
        await Assert.That(() => Check(options => options.UserAgent = " ").StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWithNoMessage()
    {
        await Assert.That(() => Check(options => options.Message = "").StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task SaysWhichSettingIsWrong()
    {
        var thrown = await Assert.That(() => Check(options => options.BreachThreshold = 0).StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();

        await Assert.That(thrown!.Message).Contains("PasswordValidation:Hibp:BreachThreshold");
    }
}
