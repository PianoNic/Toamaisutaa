using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class ExternalLoginProvisionerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    private static (ExternalLoginProvisioner Provisioner, FakeStore Store, FixedTimeProvider Clock) Build(
        ProfileSyncMode mode = ProfileSyncMode.OnChange)
    {
        var clock = new FixedTimeProvider(Now);
        var store = new FakeStore(clock);
        var options = Options.Create(new ToamaisutaaProvisioningOptions { ProfileSyncMode = mode });

        var provisioner = new ExternalLoginProvisioner(
            new DefaultClaimsProfileMapper(options),
            new DefaultProvisioningPolicy(),
            store,
            store,
            options,
            clock,
            NullLogger<ExternalLoginProvisioner>.Instance);

        return (provisioner, store, clock);
    }

    private static System.Security.Claims.ClaimsPrincipal Principal(string displayName = "Niclas") =>
        ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("iss", "https://id.example.com"),
            ("preferred_username", "pianonic"),
            ("email", "nic@example.com"),
            ("name", displayName));

    [Test]
    public async Task FirstSignInCreatesTheUserAndTheLink()
    {
        var (provisioner, store, _) = Build();

        var user = await provisioner.ProvisionAsync(Principal());

        await Assert.That(store.Users.Count).IsEqualTo(1);
        await Assert.That(store.Logins.Count).IsEqualTo(1);
        await Assert.That(user.DisplayName).IsEqualTo("Niclas");
        await Assert.That(store.Logins[0].UserId).IsEqualTo(user.Id);
        await Assert.That(store.Logins[0].Subject).IsEqualTo("abc-123");
        await Assert.That(store.Logins[0].Issuer).IsEqualTo("https://id.example.com");
    }

    [Test]
    public async Task SecondSignInReturnsTheSameUser()
    {
        var (provisioner, store, _) = Build();

        var first = await provisioner.ProvisionAsync(Principal());
        var second = await provisioner.ProvisionAsync(Principal());

        await Assert.That(second.Id).IsEqualTo(first.Id);
        await Assert.That(store.Users.Count).IsEqualTo(1);
        await Assert.That(store.Logins.Count).IsEqualTo(1);
    }

    // The bug this design exists to fix: gaggaotaku wrote the user row on every single request.
    [Test]
    public async Task AnUnchangedProfileIsNotWrittenAgain()
    {
        var (provisioner, store, _) = Build();

        await provisioner.ProvisionAsync(Principal());
        await provisioner.ProvisionAsync(Principal());
        await provisioner.ProvisionAsync(Principal());

        await Assert.That(store.ProfileUpdates).IsEqualTo(0);
    }

    [Test]
    public async Task AChangedProfileIsWrittenOnce()
    {
        var (provisioner, store, _) = Build();

        await provisioner.ProvisionAsync(Principal());
        var user = await provisioner.ProvisionAsync(Principal("Nic"));

        await Assert.That(store.ProfileUpdates).IsEqualTo(1);
        await Assert.That(user.DisplayName).IsEqualTo("Nic");
    }

    [Test]
    public async Task EveryRequestModeWritesEveryTime()
    {
        var (provisioner, store, _) = Build(ProfileSyncMode.EveryRequest);

        await provisioner.ProvisionAsync(Principal());
        await provisioner.ProvisionAsync(Principal());

        await Assert.That(store.ProfileUpdates).IsEqualTo(1);
    }

    [Test]
    public async Task NeverModeLeavesTheStoredProfileAlone()
    {
        var (provisioner, store, _) = Build(ProfileSyncMode.Never);

        await provisioner.ProvisionAsync(Principal());
        var user = await provisioner.ProvisionAsync(Principal("Nic"));

        await Assert.That(store.ProfileUpdates).IsEqualTo(0);
        await Assert.That(user.DisplayName).IsEqualTo("Niclas");
    }

    [Test]
    public async Task TheSignInStampIsNotWrittenOnEveryRequest()
    {
        var (provisioner, store, _) = Build();

        await provisioner.ProvisionAsync(Principal());
        await provisioner.ProvisionAsync(Principal());

        await Assert.That(store.SignInStamps).IsEqualTo(0);
    }

    [Test]
    public async Task TheSignInStampIsWrittenOnceItIsStale()
    {
        var (provisioner, store, clock) = Build();

        await provisioner.ProvisionAsync(Principal());
        clock.Now = Now.AddHours(2);
        await provisioner.ProvisionAsync(Principal());

        await Assert.That(store.SignInStamps).IsEqualTo(1);
        await Assert.That(store.Logins[0].LastSignInAt).IsEqualTo(Now.AddHours(2));
    }

    // Two first requests for the same never-seen subject. The loser's link is rejected by the
    // unique index; it re-reads and uses the row the winner created, rather than throwing at a user
    // whose only mistake was opening two tabs. Cleaning up the loser's user row is the store's job,
    // so this fake still holds it.
    [Test]
    public async Task AConcurrentFirstSignInResolvesToTheWinnersUser()
    {
        var (provisioner, store, clock) = Build();

        var winner = new ToamaisutaaUser
        {
            Id = Guid.CreateVersion7(clock.GetUtcNow()),
            UserName = "pianonic",
            Email = "nic@example.com",
            DisplayName = "Niclas",
        };

        store.WinnerOfTheNextRace = winner;

        var user = await provisioner.ProvisionAsync(Principal());

        await Assert.That(user.Id).IsEqualTo(winner.Id);
        await Assert.That(store.Logins.Count).IsEqualTo(1);
        await Assert.That(store.LinkAttempts).IsEqualTo(1);
    }
}
