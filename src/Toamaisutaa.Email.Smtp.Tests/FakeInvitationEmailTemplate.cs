using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeInvitationEmailTemplate : IInvitationEmailTemplate
{
    public InvitationEmailContent Content { get; set; } = new()
    {
        Subject = "Finish setting up your account",
        PlainTextBody = "finish it",
    };

    public InvitationEmailContent Build(ToamaisutaaUser user, string invitationToken) => Content;
}
