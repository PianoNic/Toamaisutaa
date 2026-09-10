using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>Refuses to start rather than failing on the first password anybody chooses, the same
/// reasoning <c>PasswordLoginStartupCheck</c> uses for local login.</summary>
internal sealed class HibpStartupCheck(IOptions<ToamaisutaaHibpOptions> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        if (settings.BreachThreshold < 1)
            problems.Add($"PasswordValidation:Hibp:BreachThreshold is {settings.BreachThreshold}. It counts appearances in the corpus, so the lowest value that refuses anything real is 1.");

        if (string.IsNullOrWhiteSpace(settings.ApiBaseAddress) || !Uri.TryCreate(settings.ApiBaseAddress, UriKind.Absolute, out _))
            problems.Add("PasswordValidation:Hibp:ApiBaseAddress is not set or is not an absolute URI.");

        if (settings.Timeout <= TimeSpan.Zero)
            problems.Add($"PasswordValidation:Hibp:Timeout is {settings.Timeout}, so every lookup would be abandoned before it started.");

        if (string.IsNullOrWhiteSpace(settings.UserAgent))
            problems.Add("PasswordValidation:Hibp:UserAgent is not set. The range API refuses requests that do not send one.");

        if (string.IsNullOrWhiteSpace(settings.Message))
            problems.Add("PasswordValidation:Hibp:Message is not set, so a breached password would be refused with no reason given.");

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa HIBP password validation is registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
