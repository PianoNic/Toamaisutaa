using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpEmailVerificationNotifierTests
{
    private const string VerificationToken = "the-raw-verification-token";

    private static ToamaisutaaUser User(string? email = "ada@example.com") => new()
    {
        Id = Guid.NewGuid(),
        Email = email,
        SecurityStamp = "stamp",
    };

    private static (SmtpEmailVerificationNotifier Notifier, FakeSmtpMessageSender Sender, FakeLogger<SmtpEmailVerificationNotifier> Logger) Build()
    {
        var sender = new FakeSmtpMessageSender();
        var logger = new FakeLogger<SmtpEmailVerificationNotifier>();
        var options = Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com", FromDisplayName = "Example App" });

        var notifier = new SmtpEmailVerificationNotifier(new FakeEmailVerificationEmailTemplate(), sender, options, logger);

        return (notifier, sender, logger);
    }

    // The whole mechanism of a change of address: the link goes to the mailbox being claimed, never
    // to the one the account already has.
    [Test]
    public async Task SendsToTheAddressBeingVerifiedRatherThanTheOneOnTheAccount()
    {
        var (notifier, sender, _) = Build();

        await notifier.SendAsync(User(email: "old@example.com"), "moved@example.com", VerificationToken);

        await Assert.That(sender.Sent).IsNotNull();
        var message = sender.Sent!;

        await Assert.That(message.Subject).IsEqualTo("Verify your email address");
        await Assert.That(message.From.Mailboxes.Single().Address).IsEqualTo("noreply@example.com");
        await Assert.That(message.To.Mailboxes.Single().Address).IsEqualTo("moved@example.com");
    }

    // The token is a credential the moment it exists in the clear - see the enrolment response rule
    // this package follows everywhere else. Nothing here may log it.
    [Test]
    public async Task NeverLogsTheVerificationToken()
    {
        var (notifier, _, logger) = Build();

        await notifier.SendAsync(User(), "moved@example.com", VerificationToken);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(VerificationToken, StringComparison.Ordinal))).IsFalse();
    }
}
