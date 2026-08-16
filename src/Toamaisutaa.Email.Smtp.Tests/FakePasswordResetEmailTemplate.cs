using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakePasswordResetEmailTemplate : IPasswordResetEmailTemplate
{
    public PasswordResetEmailContent Content { get; set; } = new()
    {
        Subject = "Reset your password",
        PlainTextBody = "reset it",
    };

    public PasswordResetEmailContent Build(ToamaisutaaUser user, string resetToken) => Content;
}
