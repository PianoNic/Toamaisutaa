using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpInvitationNotifierTests
{
    private const string InvitationToken = "the-raw-invitation-token";

    private static ToamaisutaaUser User(string? email = "ada@example.com") => new()
    {
        Id = Guid.NewGuid(),
        Email = email,
        SecurityStamp = "stamp",
    };

    private static (SmtpInvitationNotifier Notifier, FakeSmtpMessageSender Sender, FakeLogger<SmtpInvitationNotifier> Logger) Build()
    {
        var sender = new FakeSmtpMessageSender();
        var logger = new FakeLogger<SmtpInvitationNotifier>();
        var options = Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com", FromDisplayName = "Example App" });

        var notifier = new SmtpInvitationNotifier(new FakeInvitationEmailTemplate(), sender, options, logger);

        return (notifier, sender, logger);
    }

    [Test]
    public async Task SendsTheMessageBuiltByTheTemplate()
    {
        var (notifier, sender, _) = Build();

        await notifier.SendAsync(User(), InvitationToken);

        await Assert.That(sender.Sent).IsNotNull();
        var message = sender.Sent!;

        await Assert.That(message.Subject).IsEqualTo("Finish setting up your account");
        await Assert.That(message.From.Mailboxes.Single().Address).IsEqualTo("noreply@example.com");
        await Assert.That(message.To.Mailboxes.Single().Address).IsEqualTo("ada@example.com");
    }

    [Test]
    public async Task SkipsSendingWhenTheUserHasNoEmail()
    {
        var (notifier, sender, logger) = Build();

        await notifier.SendAsync(User(email: null), InvitationToken);

        await Assert.That(sender.Sent).IsNull();
        await Assert.That(logger.Entries.Any(entry => entry.Level == LogLevel.Warning)).IsTrue();
    }

    // The token is a long-lived credential the moment it exists in the clear - see the enrolment
    // response rule this package follows everywhere else. Nothing here may log it.
    [Test]
    public async Task NeverLogsTheInvitationToken()
    {
        var (notifier, _, logger) = Build();

        await notifier.SendAsync(User(), InvitationToken);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(InvitationToken, StringComparison.Ordinal))).IsFalse();
    }
}
