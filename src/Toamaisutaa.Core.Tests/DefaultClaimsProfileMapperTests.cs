using System.Security.Claims;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class DefaultClaimsProfileMapperTests
{
    private static DefaultClaimsProfileMapper Mapper(ToamaisutaaClaimNames? names = null) =>
        new(Options.Create(new ToamaisutaaProvisioningOptions { ClaimNames = names ?? new ToamaisutaaClaimNames() }));

    [Test]
    public async Task ReadsEveryClaimItKnows()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("iss", "https://id.example.com"),
            ("preferred_username", "pianonic"),
            ("email", "nic@example.com"),
            ("name", "Niclas"),
            ("picture", "https://example.com/avatar.png")));

        await Assert.That(profile.Subject).IsEqualTo("abc-123");
        await Assert.That(profile.Issuer).IsEqualTo("https://id.example.com");
        await Assert.That(profile.UserName).IsEqualTo("pianonic");
        await Assert.That(profile.Email).IsEqualTo("nic@example.com");
        await Assert.That(profile.DisplayName).IsEqualTo("Niclas");
        await Assert.That(profile.PictureUrl).IsEqualTo("https://example.com/avatar.png");
    }

    [Test]
    public async Task LeavesOptionalClaimsNullWhenAbsent()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(("sub", "abc-123")));

        await Assert.That(profile.UserName).IsNull();
        await Assert.That(profile.Email).IsNull();
        await Assert.That(profile.DisplayName).IsNull();
        await Assert.That(profile.PictureUrl).IsNull();
        await Assert.That(profile.Issuer).IsNull();
    }

    [Test]
    public async Task TreatsBlankClaimValuesAsAbsent()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("email", "   "),
            ("name", "")));

        await Assert.That(profile.Email).IsNull();
        await Assert.That(profile.DisplayName).IsNull();
    }

    // The display name is shown to people, so the human's name beats the handle. ICurrentUser.Name
    // deliberately orders these the other way round, because an audit line wants the handle.
    [Test]
    public async Task DisplayNamePrefersTheHumanName()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("preferred_username", "pianonic"),
            ("email", "nic@example.com"),
            ("name", "Niclas")));

        await Assert.That(profile.DisplayName).IsEqualTo("Niclas");
    }

    [Test]
    public async Task DisplayNameFallsBackToTheUserName()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("preferred_username", "pianonic"),
            ("email", "nic@example.com")));

        await Assert.That(profile.DisplayName).IsEqualTo("pianonic");
    }

    [Test]
    public async Task DisplayNameFallsBackToTheEmail()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(
            ("sub", "abc-123"),
            ("email", "nic@example.com")));

        await Assert.That(profile.DisplayName).IsEqualTo("nic@example.com");
    }

    [Test]
    public async Task DisplayNameIsNullWhenNothingInTheChainIsPresent()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With(("sub", "abc-123")));

        await Assert.That(profile.DisplayName).IsNull();
    }

    [Test]
    public async Task FallsBackToTheMappedNameIdentifierForTheSubject()
    {
        var profile = Mapper().Map(ClaimsPrincipals.With((ClaimTypes.NameIdentifier, "abc-123")));

        await Assert.That(profile.Subject).IsEqualTo("abc-123");
    }

    [Test]
    public async Task ThrowsWhenThereIsNoSubject()
    {
        var principal = ClaimsPrincipals.With(("email", "nic@example.com"));

        await Assert.That(() => Mapper().Map(principal)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task HonoursCustomClaimNames()
    {
        var names = new ToamaisutaaClaimNames
        {
            Subject = "oid",
            UserName = "upn",
            DisplayName = "display_name",
        };

        var profile = Mapper(names).Map(ClaimsPrincipals.With(
            ("oid", "azure-1"),
            ("upn", "nic@example.com"),
            ("display_name", "Niclas")));

        await Assert.That(profile.Subject).IsEqualTo("azure-1");
        await Assert.That(profile.UserName).IsEqualTo("nic@example.com");
        await Assert.That(profile.DisplayName).IsEqualTo("Niclas");
    }
}
