using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpPasswordResetNotifierTests
{
    private const string ResetToken = "the-raw-reset-token";

    private static ToamaisutaaUser User(string? email = "ada@example.com") => new()
    {
        Id = Guid.NewGuid(),
        UserName = "ada",
        Email = email,
        DisplayName = "Ada Lovelace",
        SecurityStamp = "stamp",
    };

    private static (SmtpPasswordResetNotifier Notifier, FakeSmtpMessageSender Sender, FakeLogger<SmtpPasswordResetNotifier> Logger) Build()
    {
        var sender = new FakeSmtpMessageSender();
        var logger = new FakeLogger<SmtpPasswordResetNotifier>();
        var options = Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com", FromDisplayName = "Example App" });

        var notifier = new SmtpPasswordResetNotifier(new FakePasswordResetEmailTemplate(), sender, options, logger);

        return (notifier, sender, logger);
    }

    [Test]
    public async Task SendsTheMessageBuiltByTheTemplate()
    {
        var (notifier, sender, _) = Build();

        await notifier.SendAsync(User(), ResetToken);

        await Assert.That(sender.Sent).IsNotNull();
        var message = sender.Sent!;

        await Assert.That(message.Subject).IsEqualTo("Reset your password");
        await Assert.That(message.From.Mailboxes.Single().Address).IsEqualTo("noreply@example.com");
        await Assert.That(message.To.Mailboxes.Single().Address).IsEqualTo("ada@example.com");
    }

    [Test]
    public async Task SkipsSendingWhenTheUserHasNoEmail()
    {
        var (notifier, sender, logger) = Build();

        await notifier.SendAsync(User(email: null), ResetToken);

        await Assert.That(sender.Sent).IsNull();
        await Assert.That(logger.Entries.Any(entry => entry.Level == LogLevel.Warning)).IsTrue();
    }

    // The token is a long-lived credential the moment it exists in the clear - see the enrolment
    // response rule this package follows everywhere else. Nothing here may log it.
    [Test]
    public async Task NeverLogsTheResetToken()
    {
        var (notifier, _, logger) = Build();

        await notifier.SendAsync(User(), ResetToken);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(ResetToken, StringComparison.Ordinal))).IsFalse();
    }
}
