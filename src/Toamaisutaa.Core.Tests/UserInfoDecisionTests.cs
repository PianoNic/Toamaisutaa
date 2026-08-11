namespace Toamaisutaa.Core.Tests;

public class UserInfoDecisionTests
{
    [Test]
    public async Task FetchesWhenTheRoleClaimIsMissing()
    {
        var principal = ClaimsPrincipals.With(("sub", "abc-123"));

        await Assert.That(UserInfoDecision.ShouldFetch(enabled: true, principal, "roles")).IsTrue();
    }

    // An issuer that already puts roles in the access token pays nothing for enrichment.
    [Test]
    public async Task SkipsWhenTheTokenAlreadyAnsweredTheQuestion()
    {
        var principal = ClaimsPrincipals.With(("sub", "abc-123"), ("roles", "admin"));

        await Assert.That(UserInfoDecision.ShouldFetch(enabled: true, principal, "roles")).IsFalse();
    }

    [Test]
    public async Task LooksAtTheConfiguredClaimAndNotAnyOtherOne()
    {
        var principal = ClaimsPrincipals.With(("sub", "abc-123"), ("roles", "admin"));

        await Assert.That(UserInfoDecision.ShouldFetch(enabled: true, principal, "groups")).IsTrue();
    }

    [Test]
    public async Task SkipsWhenDisabled()
    {
        var principal = ClaimsPrincipals.With(("sub", "abc-123"));

        await Assert.That(UserInfoDecision.ShouldFetch(enabled: false, principal, "roles")).IsFalse();
    }

    [Test]
    public async Task SkipsWithoutAPrincipal()
    {
        await Assert.That(UserInfoDecision.ShouldFetch(enabled: true, principal: null, "roles")).IsFalse();
    }

    [Test]
    public async Task SkipsWhenNoRoleClaimIsConfigured()
    {
        var principal = ClaimsPrincipals.With(("sub", "abc-123"));

        await Assert.That(UserInfoDecision.ShouldFetch(enabled: true, principal, "  ")).IsFalse();
    }
}
