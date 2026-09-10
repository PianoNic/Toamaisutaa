using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The one place a local session is minted, driven directly.
/// </summary>
/// <remarks>
/// It stopped being private to the password path when passkeys arrived: a WebAuthn assertion ends
/// in exactly this token pair, from a package Core cannot reference. What is asserted here is the
/// part both callers depend on and neither owns - what the token claims, and what the refresh row
/// keeps so that a rotation can claim it again.
/// </remarks>
public class LocalSessionIssuerTests
{
    /// <summary>
    /// A passkey sign-in proves possession and verifies the person in one gesture, so telling that
    /// user to go and enrol a second factor is telling the one who did the most work to do more.
    /// </summary>
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

    /// <summary>The other half of the same rule: a session that proved nothing but a password is
    /// still told to enrol, or the short circuit above would switch enforcement off entirely.</summary>
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
    /// The rule this repository has been bitten by three times, asked of a fourth claim: the refresh
    /// row has to carry what the token claims, or a rotation an access-token lifetime later reports
    /// a passkey session as a password-only one.
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

    /// <summary>A refresh renewed something rather than proving it, and an audit table that counted
    /// rotations as sign-ins would report one every access-token lifetime for an open tab.</summary>
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
