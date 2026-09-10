using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

internal sealed class FakeMagicLinkEmailTemplate : IMagicLinkEmailTemplate
{
    public MagicLinkEmailContent Content { get; set; } = new()
    {
        Subject = "Your sign-in link",
        PlainTextBody = "sign in",
    };

    public MagicLinkEmailContent Build(ToamaisutaaUser user, string magicLinkToken) => Content;
}
