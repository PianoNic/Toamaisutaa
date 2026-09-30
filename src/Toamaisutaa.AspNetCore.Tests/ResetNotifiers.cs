using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Hands back the reset token, which is otherwise only ever seen by the notifier. Locked,
/// because queued mail for parallel requests is handed over from more than one thread.</summary>
internal sealed class CapturingResetNotifier(List<string> issued) : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        lock (issued)
            issued.Add(resetToken);

        return Task.CompletedTask;
    }
}
