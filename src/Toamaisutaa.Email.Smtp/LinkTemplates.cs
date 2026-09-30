namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The link options the default templates build their links from, read and checked by one rule so
/// the startup checks and the templates cannot disagree about what a usable one is.
/// </summary>
internal static class LinkTemplates
{
    internal static string Build(string? template, string optionName, string token)
    {
        // Validated at startup, so this is only reachable if the option was never set - which is
        // itself a caller error, since the default template cannot invent a page it knows nothing
        // about. A missing link is better than a wrong one.
        if (string.IsNullOrWhiteSpace(template))
            throw new InvalidOperationException($"Email:Smtp:{optionName} is not set.");

        return template.Replace("{token}", Uri.EscapeDataString(token), StringComparison.Ordinal);
    }

    /// <summary>What is wrong with a link option, or null when the default template can use it.
    /// <paramref name="mail"/> is what the message calls the email - "reset", "sign-in" - and
    /// <paramref name="templateInterface"/> the template a consumer can register to do without it.</summary>
    internal static string? Problem(string? template, string optionName, string mail, string templateInterface)
    {
        if (string.IsNullOrWhiteSpace(template))
        {
            return $"Email:Smtp:{optionName} is not set. The default template needs it to build the link the {mail} email "
                + $"points at - or register your own {templateInterface} that does not need it.";
        }

        if (!template.Contains("{token}", StringComparison.Ordinal))
            return $"Email:Smtp:{optionName} does not contain \"{{token}}\", so every {mail} link would point at the same place.";

        return null;
    }
}
