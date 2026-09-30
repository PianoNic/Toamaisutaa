namespace Toamaisutaa.Core;

/// <summary>
/// The one shape every startup check refuses in: a heading, then one indented line per problem, so a
/// misconfiguration reads the same whichever package found it.
/// </summary>
internal static class StartupProblems
{
    internal static InvalidOperationException Refusal(string heading, IEnumerable<string> problems) =>
        new(heading + Environment.NewLine + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
}
