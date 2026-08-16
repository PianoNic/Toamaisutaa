using MimeKit;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeSmtpMessageSender : ISmtpMessageSender
{
    public MimeMessage? Sent { get; private set; }

    public Task SendAsync(MimeMessage message, CancellationToken cancellationToken)
    {
        Sent = message;
        return Task.CompletedTask;
    }
}
