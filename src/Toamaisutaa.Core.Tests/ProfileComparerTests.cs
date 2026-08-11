using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class ProfileComparerTests
{
    private static ToamaisutaaUser User() => new()
    {
        Id = Guid.CreateVersion7(),
        UserName = "pianonic",
        Email = "nic@example.com",
        DisplayName = "Niclas",
        PictureUrl = "https://example.com/avatar.png",
    };

    private static ExternalUserProfile Profile() => new()
    {
        Subject = "abc-123",
        UserName = "pianonic",
        Email = "nic@example.com",
        DisplayName = "Niclas",
        PictureUrl = "https://example.com/avatar.png",
    };

    [Test]
    public async Task IdenticalValuesAreNotAChange()
    {
        await Assert.That(ProfileComparer.HasChanges(User(), Profile())).IsFalse();
    }

    [Test]
    public async Task ADifferentDisplayNameIsAChange()
    {
        await Assert.That(ProfileComparer.HasChanges(User(), Profile() with { DisplayName = "Nic" })).IsTrue();
    }

    [Test]
    public async Task ADifferentEmailIsAChange()
    {
        await Assert.That(ProfileComparer.HasChanges(User(), Profile() with { Email = "other@example.com" })).IsTrue();
    }

    [Test]
    public async Task ADifferentPictureIsAChange()
    {
        await Assert.That(ProfileComparer.HasChanges(User(), Profile() with { PictureUrl = null })).IsTrue();
    }

    [Test]
    public async Task AValueAppearingIsAChange()
    {
        var user = User();
        user.UserName = null;

        await Assert.That(ProfileComparer.HasChanges(user, Profile())).IsTrue();
    }

    // An issuer that sends an empty string is saying nothing, not saying "clear it".
    [Test]
    public async Task BlankAndAbsentAreTheSameValue()
    {
        var user = User();
        user.PictureUrl = null;

        await Assert.That(ProfileComparer.HasChanges(user, Profile() with { PictureUrl = "  " })).IsFalse();
    }
}
