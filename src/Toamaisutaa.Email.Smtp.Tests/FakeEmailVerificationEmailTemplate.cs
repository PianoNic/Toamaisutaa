using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeEmailVerificationEmailTemplate : IEmailVerificationEmailTemplate
{
    public EmailVerificationEmailContent Content { get; set; } = new()
    {
        Subject = "Verify your email address",
        PlainTextBody = "confirm it",
    };

    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken) => Content;
}
