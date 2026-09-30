using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class MailRequestCooldownTests
{
    /// <summary>
    /// The sweep saw an expired entry, a request renewed it, and the sweep removed it anyway, so the
    /// next request for that address went straight through the cooldown.
    /// </summary>
    [Test]
    public async Task A_sweep_does_not_remove_an_entry_renewed_after_it_looked()
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var cooldown = new MailRequestCooldown(
            Options.Create(new ToamaisutaaLocalLoginOptions { MailRequestCooldown = TimeSpan.FromMinutes(1) }),
            time);

        await Assert.That(cooldown.TryEnter("reset", "victim@example.com")).IsTrue();

        time.Advance(TimeSpan.FromMinutes(2));

        var renewed = false;
        cooldown.BeforeSweepRemoves = _ =>
        {
            cooldown.BeforeSweepRemoves = null;
            renewed = cooldown.TryEnter("reset", "victim@example.com");
        };

        // Any address starts the sweep; this one is the request that races it.
        cooldown.TryEnter("reset", "someone@example.com");

        await Assert.That(renewed).IsTrue();
        await Assert.That(cooldown.TryEnter("reset", "victim@example.com")).IsFalse();
    }
}
