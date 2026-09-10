using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpAdminPasswordIssuedNotifierTests
{
    private const string IssuedPassword = "the-raw-issued-password";

    private static ToamaisutaaUser User(string? email = "ada@example.com") => new()
    {
        Id = Guid.NewGuid(),
        UserName = "ada",
        Email = email,
        DisplayName = "Ada Lovelace",
        SecurityStamp = "stamp",
    };

    private static (SmtpAdminPasswordIssuedNotifier Notifier, FakeSmtpMessageSender Sender, FakeLogger<SmtpAdminPasswordIssuedNotifier> Logger) Build()
    {
        var sender = new FakeSmtpMessageSender();
        var logger = new FakeLogger<SmtpAdminPasswordIssuedNotifier>();
        var options = Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com", FromDisplayName = "Example App" });

        var notifier = new SmtpAdminPasswordIssuedNotifier(new FakeAdminPasswordIssuedEmailTemplate(), sender, options, logger);

        return (notifier, sender, logger);
    }

    [Test]
    public async Task SendsTheMessageBuiltByTheTemplate()
    {
        var (notifier, sender, _) = Build();

        await notifier.PasswordIssuedAsync(User(), IssuedPassword);

        await Assert.That(sender.Sent).IsNotNull();
        var message = sender.Sent!;

        await Assert.That(message.Subject).IsEqualTo("Your new password");
        await Assert.That(message.From.Mailboxes.Single().Address).IsEqualTo("noreply@example.com");
        await Assert.That(message.To.Mailboxes.Single().Address).IsEqualTo("ada@example.com");
    }

    [Test]
    public async Task SkipsSendingWhenTheUserHasNoEmail()
    {
        var (notifier, sender, logger) = Build();

        await notifier.PasswordIssuedAsync(User(email: null), IssuedPassword);

        await Assert.That(sender.Sent).IsNull();
        await Assert.That(logger.Entries.Any(entry => entry.Level == LogLevel.Warning)).IsTrue();
    }

    // The password is a credential the moment it exists in the clear - see the enrolment response
    // rule this package follows everywhere else. Nothing here may log it.
    [Test]
    public async Task NeverLogsTheIssuedPassword()
    {
        var (notifier, _, logger) = Build();

        await notifier.PasswordIssuedAsync(User(), IssuedPassword);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(IssuedPassword, StringComparison.Ordinal))).IsFalse();
    }
}
