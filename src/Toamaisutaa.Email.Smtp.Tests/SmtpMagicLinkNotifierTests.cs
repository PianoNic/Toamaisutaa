using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpMagicLinkNotifierTests
{
    private const string MagicLinkToken = "the-raw-magic-link-token";

    private static ToamaisutaaUser User(string? email = "ada@example.com") => new()
    {
        Id = Guid.NewGuid(),
        Email = email,
        SecurityStamp = "stamp",
    };

    private static (SmtpMagicLinkNotifier Notifier, FakeSmtpMessageSender Sender, FakeLogger<SmtpMagicLinkNotifier> Logger) Build()
    {
        var sender = new FakeSmtpMessageSender();
        var logger = new FakeLogger<SmtpMagicLinkNotifier>();
        var options = Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com", FromDisplayName = "Example App" });

        var notifier = new SmtpMagicLinkNotifier(new FakeMagicLinkEmailTemplate(), sender, options, logger);

        return (notifier, sender, logger);
    }

    [Test]
    public async Task SendsToTheAddressOnTheAccount()
    {
        var (notifier, sender, _) = Build();

        await notifier.SendAsync(User(), MagicLinkToken);

        await Assert.That(sender.Sent).IsNotNull();
        var message = sender.Sent!;

        await Assert.That(message.Subject).IsEqualTo("Your sign-in link");
        await Assert.That(message.From.Mailboxes.Single().Address).IsEqualTo("noreply@example.com");
        await Assert.That(message.To.Mailboxes.Single().Address).IsEqualTo("ada@example.com");
    }

    // This token is a session rather than a step towards one, so the no-logging rule matters more
    // here than anywhere else this package sends mail.
    [Test]
    public async Task NeverLogsTheMagicLinkToken()
    {
        var (notifier, _, logger) = Build();

        await notifier.SendAsync(User(), MagicLinkToken);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(MagicLinkToken, StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task SendsNothingForAnAccountWithNoAddress()
    {
        var (notifier, sender, _) = Build();

        await notifier.SendAsync(User(email: null), MagicLinkToken);

        await Assert.That(sender.Sent).IsNull();
    }
}
