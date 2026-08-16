using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpEmailStartupCheckTests
{
    private static ToamaisutaaSmtpEmailOptions Valid() => new()
    {
        Host = "smtp.example.com",
        Port = 587,
        From = "noreply@example.com",
        PasswordResetLinkTemplate = "https://app.example.com/reset?token={token}",
    };

    private static SmtpEmailStartupCheck Check(ToamaisutaaSmtpEmailOptions options, out FakeLogger<SmtpEmailStartupCheck> logger)
    {
        logger = new FakeLogger<SmtpEmailStartupCheck>();
        return new SmtpEmailStartupCheck(Options.Create(options), logger);
    }

    [Test]
    public async Task ValidOptionsStartCleanly()
    {
        await Check(Valid(), out _).StartAsync(CancellationToken.None);
    }

    [Test]
    public async Task RefusesToStartWithNoHost()
    {
        var options = Valid();
        options.Host = null;

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(70000)]
    public async Task RefusesToStartWithAnInvalidPort(int port)
    {
        var options = Valid();
        options.Port = port;

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWithNoFromAddress()
    {
        var options = Valid();
        options.From = string.Empty;

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWithAFromAddressThatIsNotAnEmail()
    {
        var options = Valid();
        options.From = "not an email";

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWithNoResetLinkTemplate()
    {
        var options = Valid();
        options.PasswordResetLinkTemplate = null;

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWhenTheResetLinkTemplateHasNoTokenPlaceholder()
    {
        var options = Valid();
        options.PasswordResetLinkTemplate = "https://app.example.com/reset";

        await Assert.That(() => Check(options, out _).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task WarnsWhenCertificateVerificationIsSkipped()
    {
        var options = Valid();
        options.SkipCertificateVerification = true;

        var check = Check(options, out var logger);
        await check.StartAsync(CancellationToken.None);

        await Assert.That(logger.Entries.Any(entry => entry.Level == LogLevel.Warning)).IsTrue();
    }
}
