using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeAdminPasswordIssuedEmailTemplate : IAdminPasswordIssuedEmailTemplate
{
    public AdminPasswordIssuedEmailContent Content { get; set; } = new()
    {
        Subject = "Your new password",
        PlainTextBody = "here it is",
    };

    public AdminPasswordIssuedEmailContent Build(ToamaisutaaUser user, string rawPassword) => Content;
}
