using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeEmailVerificationEmailTemplate : IEmailVerificationEmailTemplate
{
    public EmailVerificationEmailContent Content { get; set; } = new()
    {
        Subject = "Verify your email address",
        PlainTextBody = "confirm it",
    };

    public EmailVerificationContext? Context { get; private set; }

    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken) => Content;

    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken, EmailVerificationContext context)
    {
        Context = context;
        return Content;
    }
}
