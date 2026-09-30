using MimeKit;

namespace Toamaisutaa.Email.Smtp;

internal static class SmtpMessages
{
    /// <summary>
    /// Addressed to the bare address, never with the user's display name: that name is theirs to
    /// choose, and the mailbox it would be put in front of has not always been proven to be theirs.
    /// </summary>
    internal static MimeMessage Create(
        ToamaisutaaSmtpEmailOptions settings,
        string to,
        string subject,
        string plainTextBody,
        string? htmlBody)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings.FromDisplayName ?? string.Empty, settings.From));
        message.To.Add(new MailboxAddress(string.Empty, to));
        message.Subject = subject;

        var body = new BodyBuilder { TextBody = plainTextBody, HtmlBody = htmlBody };
        message.Body = body.ToMessageBody();

        return message;
    }
}
