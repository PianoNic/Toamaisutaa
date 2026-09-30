using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class LocalSessionIssuerTests
{
    [Test]
    public async Task A_session_that_presented_a_second_factor_is_never_told_to_enrol()
    {
        var harness = PasswordHarness.Create(
            configureTwoFactor: options => options.Enforcement = TwoFactorEnforcement.RequiredForAll,
            withTwoFactor: true);

        var user = await harness.Users.CreateAsync(new ToamaisutaaUser { UserName = "ada", SecurityStamp = "stamp" });

        await harness.SessionIssuer.IssueAsync(Request(user, TwoFactorSource.Passkey), CancellationToken.None);

        // Not enrolled in TOTP and enforcement demands it, so the gate on its own would say yes.
        await Assert.That(harness.Issuer.Issued[^1].TwoFactorEnrolmentRequired).IsFalse();
    }

    [Test]
    public async Task A_session_with_no_second_factor_is_still_told_to_enrol()
    {
        var harness = PasswordHarness.Create(
            configureTwoFactor: options => options.Enforcement = TwoFactorEnforcement.RequiredForAll,
            withTwoFactor: true);

        var user = await harness.Users.CreateAsync(new ToamaisutaaUser { UserName = "ada", SecurityStamp = "stamp" });

        await harness.SessionIssuer.IssueAsync(Request(user, twoFactorSource: null), CancellationToken.None);

        await Assert.That(harness.Issuer.Issued[^1].TwoFactorEnrolmentRequired).IsTrue();
    }

    /// <summary>
    /// The refresh row has to carry what the token claims, or a rotation an access-token lifetime
    /// later reports a passkey session as a password-only one.
    /// </summary>
    [Test]
    public async Task The_refresh_row_carries_what_the_token_claimed()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.Users.CreateAsync(new ToamaisutaaUser { UserName = "ada", SecurityStamp = "stamp" });

        var issued = await harness.SessionIssuer.IssueAsync(Request(user, TwoFactorSource.Passkey), CancellationToken.None);

        var stored = await harness.Passwords.FindByHashAsync(SecureTokens.HashToken(issued.Tokens.RefreshToken));

        await Assert.That(stored).IsNotNull();
        await Assert.That(stored!.AuthenticationMethods).IsEqualTo("hwk user mfa");
        await Assert.That(stored.TwoFactorSource).IsEqualTo(TwoFactorSource.Passkey);
        await Assert.That(stored.SecondFactorAt).IsEqualTo(PasswordHarness.Start);
        await Assert.That(stored.FamilyId).IsEqualTo(issued.FamilyId);
    }

    [Test]
    public async Task A_rotation_publishes_no_sign_in()
    {
        var harness = PasswordHarness.Create();
        var user = await harness.Users.CreateAsync(new ToamaisutaaUser { UserName = "ada", SecurityStamp = "stamp" });

        var first = await harness.SessionIssuer.IssueAsync(Request(user, TwoFactorSource.Passkey), CancellationToken.None);

        await harness.SessionIssuer.IssueAsync(
            Request(user, TwoFactorSource.Passkey) with { FamilyId = first.FamilyId, NewSignIn = false },
            CancellationToken.None);

        await Assert.That(harness.Events.OfKind<SignInSucceeded>()).HasCount().EqualTo(1);
    }

    private static LocalSessionRequest Request(ToamaisutaaUser user, string? twoFactorSource) => new()
    {
        User = user,
        Methods = twoFactorSource is null
            ? [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod]
            : [ToamaisutaaDefaults.HardwareKeyMethod, ToamaisutaaDefaults.UserPresenceMethod, ToamaisutaaDefaults.MultiFactorMethod],
        TwoFactorSource = twoFactorSource,
        SecondFactorAt = twoFactorSource is null ? null : PasswordHarness.Start,
        NewSignIn = true,
        Client = new ClientMetadata.SessionClient(null, null),
        Now = PasswordHarness.Start,
    };
}
