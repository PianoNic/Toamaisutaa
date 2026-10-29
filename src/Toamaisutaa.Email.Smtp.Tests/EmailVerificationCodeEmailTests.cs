using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class EmailVerificationCodeEmailTests
{
    private static readonly ToamaisutaaUser User = new() { Id = Guid.NewGuid(), Email = "old@example.com", DisplayName = "Click here", SecurityStamp = "stamp" };

    private static IEmailVerificationEmailTemplate DefaultTemplate() =>
        new DefaultEmailVerificationEmailTemplate(Options.Create(new ToamaisutaaSmtpEmailOptions { EmailVerificationLinkTemplate = "https://app.example/verify?token={token}" }));

    [Test]
    public async Task The_default_mail_carries_the_code_and_how_long_it_lasts()
    {
        var content = DefaultTemplate().BuildCode(User, "ada@example.com", "123456", TimeSpan.FromMinutes(15));

        await Assert.That(content.Subject).IsEqualTo("Your verification code is 123456");
        await Assert.That(content.PlainTextBody).Contains("Your verification code is 123456");
        await Assert.That(content.PlainTextBody).Contains("15 minutes");
        await Assert.That(content.HtmlBody!).Contains("123456");
    }

    /// <summary>A registrant chooses their own name and this goes to an address nobody has proven.</summary>
    [Test]
    public async Task The_default_mail_greets_nobody_by_name()
    {
        var content = DefaultTemplate().BuildCode(User, "ada@example.com", "123456", TimeSpan.FromMinutes(15));

        await Assert.That(content.PlainTextBody).DoesNotContain("Click here");
        await Assert.That(content.HtmlBody!).DoesNotContain("Click here");
    }

    [Test]
    public async Task The_notifier_sends_the_code_to_the_address_being_verified()
    {
        var sender = new FakeSmtpMessageSender();
        var notifier = new SmtpEmailVerificationNotifier(
            DefaultTemplate(),
            sender,
            Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com" }),
            new FakeLogger<SmtpEmailVerificationNotifier>());

        IEmailVerificationNotifier asInterface = notifier;
        await asInterface.SendCodeAsync(User, "ada@example.com", "654321", TimeSpan.FromMinutes(15));

        await Assert.That(sender.Sent).IsNotNull();
        await Assert.That(sender.Sent!.To.Mailboxes.Single().Address).IsEqualTo("ada@example.com");
        await Assert.That(sender.Sent.Subject).IsEqualTo("Your verification code is 654321");
    }

    [Test]
    public async Task A_template_of_your_own_replaces_the_wording()
    {
        var sender = new FakeSmtpMessageSender();
        var notifier = new SmtpEmailVerificationNotifier(
            new CodeTemplate(),
            sender,
            Options.Create(new ToamaisutaaSmtpEmailOptions { From = "noreply@example.com" }),
            new FakeLogger<SmtpEmailVerificationNotifier>());

        await notifier.SendCodeAsync(User, "ada@example.com", "654321", TimeSpan.FromMinutes(15));

        await Assert.That(sender.Sent!.Subject).IsEqualTo("Dein Code: 654321");
    }

    private sealed class CodeTemplate : IEmailVerificationEmailTemplate
    {
        public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken) =>
            new() { Subject = "link", PlainTextBody = verificationToken };

        public EmailVerificationEmailContent BuildCode(ToamaisutaaUser user, string email, string code, TimeSpan validFor) =>
            new() { Subject = $"Dein Code: {code}", PlainTextBody = code };
    }
}
