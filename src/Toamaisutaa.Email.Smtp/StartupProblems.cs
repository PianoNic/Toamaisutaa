namespace Toamaisutaa.Email.Smtp;

/// <summary>The shape every startup check in the core package refuses in: a heading, then one
/// indented line per problem. Kept here too because this package does not reference the core one.</summary>
internal static class StartupProblems
{
    internal static InvalidOperationException Refusal(string heading, IEnumerable<string> problems) =>
        new(heading + Environment.NewLine + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
}
