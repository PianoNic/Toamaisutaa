using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The name the invitation and admin password mails greet by. The reset, verification and sign-in
/// mails deliberately greet nobody, for the reasons their templates give, so this is not a default
/// to reach for.
/// </summary>
internal static class Greeting
{
    internal static string NameOf(ToamaisutaaUser user) =>
        string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;
}
