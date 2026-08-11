using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class DefaultProvisioningPolicyTests
{
    private static readonly Guid UserId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid LoginId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static ExternalUserProfile Profile(string displayName = "Niclas") => new()
    {
        Subject = "abc-123",
        UserName = "pianonic",
        Email = "nic@example.com",
        DisplayName = displayName,
    };

    private static ToamaisutaaUser StoredUser(string displayName = "Niclas") => new()
    {
        Id = UserId,
        UserName = "pianonic",
        Email = "nic@example.com",
        DisplayName = displayName,
    };

    private static ToamaisutaaExternalLogin StoredLogin() => new()
    {
        Id = LoginId,
        UserId = UserId,
        ProviderKey = ToamaisutaaDefaults.ProviderKey,
        Subject = "abc-123",
    };

    private static ProvisioningContext Context(
        ProfileSyncMode mode,
        ToamaisutaaExternalLogin? login = null,
        ToamaisutaaUser? linkedUser = null,
        ToamaisutaaUser? candidate = null,
        string displayName = "Niclas") => new()
    {
        ProviderKey = ToamaisutaaDefaults.ProviderKey,
        Profile = Profile(displayName),
        SyncMode = mode,
        ExistingLogin = login,
        LinkedUser = linkedUser,
        LinkCandidate = candidate,
    };

    [Test]
    public async Task UnknownSubjectCreatesAUser()
    {
        var decision = new DefaultProvisioningPolicy().Decide(Context(ProfileSyncMode.OnChange));

        await Assert.That(decision.Action).IsEqualTo(ProvisioningAction.CreateNew);
        await Assert.That(decision.UserId).IsNull();
        // The insert writes the profile, so there is nothing left to update.
        await Assert.That(decision.ProfileNeedsUpdate).IsFalse();
    }

    [Test]
    public async Task KnownSubjectResolvesToItsUser()
    {
        var decision = new DefaultProvisioningPolicy()
            .Decide(Context(ProfileSyncMode.OnChange, StoredLogin(), StoredUser()));

        await Assert.That(decision.Action).IsEqualTo(ProvisioningAction.AlreadyLinked);
        await Assert.That(decision.UserId).IsEqualTo(UserId);
        await Assert.That(decision.ExternalLoginId).IsEqualTo(LoginId);
    }

    [Test]
    [Arguments(ProfileSyncMode.Never, false)]
    [Arguments(ProfileSyncMode.FirstSignInOnly, false)]
    [Arguments(ProfileSyncMode.OnChange, true)]
    [Arguments(ProfileSyncMode.EveryRequest, true)]
    public async Task ChangedProfileUpdatesOnlyWhenTheModeSaysSo(ProfileSyncMode mode, bool expected)
    {
        var decision = new DefaultProvisioningPolicy().Decide(
            Context(mode, StoredLogin(), StoredUser("Old Name"), displayName: "Niclas"));

        await Assert.That(decision.ProfileNeedsUpdate).IsEqualTo(expected);
    }

    [Test]
    [Arguments(ProfileSyncMode.Never, false)]
    [Arguments(ProfileSyncMode.FirstSignInOnly, false)]
    // The whole point of OnChange: an unchanged profile is not a write.
    [Arguments(ProfileSyncMode.OnChange, false)]
    [Arguments(ProfileSyncMode.EveryRequest, true)]
    public async Task UnchangedProfileUpdatesOnlyOnEveryRequest(ProfileSyncMode mode, bool expected)
    {
        var decision = new DefaultProvisioningPolicy().Decide(
            Context(mode, StoredLogin(), StoredUser()));

        await Assert.That(decision.ProfileNeedsUpdate).IsEqualTo(expected);
    }

    [Test]
    [Arguments(ProfileSyncMode.Never, false)]
    [Arguments(ProfileSyncMode.FirstSignInOnly, true)]
    [Arguments(ProfileSyncMode.OnChange, true)]
    [Arguments(ProfileSyncMode.EveryRequest, true)]
    public async Task LinkCandidateAttachesToTheExistingUser(ProfileSyncMode mode, bool expectedUpdate)
    {
        var decision = new DefaultProvisioningPolicy()
            .Decide(Context(mode, candidate: StoredUser("Old Name")));

        await Assert.That(decision.Action).IsEqualTo(ProvisioningAction.LinkExisting);
        await Assert.That(decision.UserId).IsEqualTo(UserId);
        await Assert.That(decision.ProfileNeedsUpdate).IsEqualTo(expectedUpdate);
    }

    [Test]
    public async Task ExistingLoginWithoutItsUserIsARefusal()
    {
        var context = Context(ProfileSyncMode.OnChange, StoredLogin());

        await Assert.That(() => new DefaultProvisioningPolicy().Decide(context)).Throws<InvalidOperationException>();
    }
}
