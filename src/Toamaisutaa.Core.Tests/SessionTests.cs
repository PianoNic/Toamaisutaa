using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class SessionTests
{
    private const string Password = "correct horse battery";

    private const string Chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0";

    /// <summary>
    /// Drops the session registration leaves behind straight out of the fake store, because
    /// <c>RevokeAllExceptAsync</c> is under test here.
    /// </summary>
    private static async Task<ToamaisutaaUser> RegisterAsync(
        PasswordHarness harness,
        string userName = "pianonic",
        string? email = "nic@example.com")
    {
        var user = await harness.RegisterAsync(userName, email, Password);
        harness.Passwords.RefreshTokens.RemoveAll(token => token.UserId == user.Id);

        return user;
    }

    private static Guid Family(SignInResult result, PasswordHarness harness) =>
        harness.Passwords.RefreshTokens
            .Single(token => token.TokenHash == SecureTokens.HashToken(result.Tokens!.RefreshToken))
            .FamilyId;

    [Test]
    public async Task A_session_records_the_user_agent_the_sign_in_carried()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        await harness.SignInAsync("pianonic", Password, userAgent: Chrome);

        var listed = await harness.Sessions.ListAsync(user.Id);

        await Assert.That(listed.Single().UserAgent).IsEqualTo(Chrome);
    }

    [Test]
    public async Task No_address_is_stored_by_default()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        await harness.SignInAsync("pianonic", Password, ipAddress: "203.0.113.42");

        await Assert.That((await harness.Sessions.ListAsync(user.Id)).Single().IpAddress).IsNull();
    }

    [Test]
    public async Task The_address_is_truncated_when_configuration_asks_for_it()
    {
        var harness = PasswordHarness.Create(options => options.IpAddressStorage = IpAddressStorage.Truncated);
        var user = await RegisterAsync(harness);

        await harness.SignInAsync("pianonic", Password, ipAddress: "203.0.113.42");

        await Assert.That((await harness.Sessions.ListAsync(user.Id)).Single().IpAddress).IsEqualTo("203.0.113.0/24");
    }

    /// <summary>
    /// Carried rather than recomputed: <c>/auth/refresh</c> is the call a background timer makes,
    /// so recomputing would describe every session as whatever last renewed it.
    /// </summary>
    [Test]
    public async Task Refreshing_carries_the_user_agent_and_the_address_onto_the_rotated_row()
    {
        var harness = PasswordHarness.Create(options => options.IpAddressStorage = IpAddressStorage.Truncated);
        var user = await RegisterAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password, userAgent: Chrome, ipAddress: "203.0.113.42");
        await harness.SignIn.RefreshAsync(signedIn.Tokens!.RefreshToken);

        var listed = (await harness.Sessions.ListAsync(user.Id)).Single();

        await Assert.That(listed.UserAgent).IsEqualTo(Chrome);
        await Assert.That(listed.IpAddress).IsEqualTo("203.0.113.0/24");
    }

    [Test]
    public async Task Refreshing_moves_the_session_s_last_used_time_and_leaves_its_start_alone()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password);
        var establishedAt = harness.Clock.Now;

        harness.Clock.Now = harness.Clock.Now.AddHours(3);
        await harness.SignIn.RefreshAsync(signedIn.Tokens!.RefreshToken);

        var listed = (await harness.Sessions.ListAsync(user.Id)).Single();

        await Assert.That(listed.CreatedAt).IsEqualTo(establishedAt);
        await Assert.That(listed.LastUsedAt).IsEqualTo(establishedAt.AddHours(3));
    }

    [Test]
    public async Task A_session_reports_the_methods_it_was_established_with()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = await RegisterAsync(harness);
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var started = await harness.SignInAsync("pianonic", Password);
        harness.Clock.Now = harness.Clock.Now.AddSeconds(30);
        await harness.VerifyAsync(started.Challenge!.Token, harness.CurrentCode(secret));

        var listed = (await harness.Sessions.ListAsync(user.Id)).Single();

        await Assert.That(listed.AuthenticationMethods).Contains(ToamaisutaaDefaults.MultiFactorMethod);
    }

    [Test]
    public async Task Two_sign_ins_are_two_sessions_and_only_the_named_one_is_current()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        var first = await harness.SignInAsync("pianonic", Password);
        var second = await harness.SignInAsync("pianonic", Password);

        var listed = await harness.Sessions.ListAsync(user.Id, Family(second, harness));

        await Assert.That(listed).HasCount().EqualTo(2);
        await Assert.That(listed.Single(session => session.IsCurrent).Id).IsEqualTo(Family(second, harness));
        await Assert.That(listed.Single(session => session.Id == Family(first, harness)).IsCurrent).IsFalse();
    }

    /// <summary>
    /// The family is refused at the next refresh rather than swept off a timer, so it is still
    /// unrotated and unrevoked in the table.
    /// </summary>
    [Test]
    public async Task A_family_past_its_absolute_lifetime_is_not_listed()
    {
        var harness = PasswordHarness.Create(options =>
        {
            options.RefreshTokenLifetime = TimeSpan.FromDays(30);
            options.RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(2);
        });

        var user = await RegisterAsync(harness);
        await harness.SignInAsync("pianonic", Password);

        harness.Clock.Now = harness.Clock.Now.AddDays(3);

        await Assert.That(await harness.Sessions.ListAsync(user.Id)).IsEmpty();
    }

    [Test]
    public async Task A_session_ends_at_the_sooner_of_its_own_expiry_and_the_family_s()
    {
        var harness = PasswordHarness.Create(options =>
        {
            options.RefreshTokenLifetime = TimeSpan.FromDays(14);
            options.RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(3);
        });

        var user = await RegisterAsync(harness);
        var establishedAt = harness.Clock.Now;

        await harness.SignInAsync("pianonic", Password);

        await Assert.That((await harness.Sessions.ListAsync(user.Id)).Single().ExpiresAt)
            .IsEqualTo(establishedAt.AddDays(3));
    }

    [Test]
    public async Task A_revoked_session_can_no_longer_refresh()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password);

        await Assert.That(await harness.Sessions.RevokeAsync(user.Id, Family(signedIn, harness))).IsTrue();

        var refreshed = await harness.SignIn.RefreshAsync(signedIn.Tokens!.RefreshToken);

        await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);
    }

    [Test]
    public async Task Revoking_someone_else_s_session_answers_false_and_leaves_it_alive()
    {
        var harness = PasswordHarness.Create();
        var ada = await RegisterAsync(harness);
        var grace = await RegisterAsync(harness, "grace", "grace@example.com");

        var hers = await harness.SignInAsync("grace", Password);

        await Assert.That(await harness.Sessions.RevokeAsync(ada.Id, Family(hers, harness))).IsFalse();
        await Assert.That(await harness.Sessions.ListAsync(grace.Id)).HasCount().EqualTo(1);
    }

    [Test]
    public async Task Revoking_a_session_that_never_existed_answers_false()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);
        await harness.SignInAsync("pianonic", Password);

        await Assert.That(await harness.Sessions.RevokeAsync(user.Id, Guid.CreateVersion7())).IsFalse();
    }

    [Test]
    public async Task Revoking_a_session_publishes_it_with_its_reason()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        var signedIn = await harness.SignInAsync("pianonic", Password);
        var session = Family(signedIn, harness);

        await harness.Sessions.RevokeAsync(user.Id, session);

        var revoked = harness.Events.Single<SessionRevoked>();

        await Assert.That(revoked.UserId).IsEqualTo(user.Id);
        await Assert.That(revoked.SessionId).IsEqualTo(session);
        await Assert.That(revoked.Reason).IsEqualTo("revoked-by-user");
    }

    [Test]
    public async Task Signing_out_everywhere_else_publishes_one_revocation_per_session()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        await harness.SignInAsync("pianonic", Password);
        await harness.SignInAsync("pianonic", Password);
        var kept = await harness.SignInAsync("pianonic", Password);

        await harness.Sessions.RevokeAllExceptAsync(user.Id, Family(kept, harness));

        var revoked = harness.Events.OfKind<SessionRevoked>().ToList();

        await Assert.That(revoked).HasCount().EqualTo(2);
        await Assert.That(revoked.Select(session => session.SessionId)).DoesNotContain(Family(kept, harness));
    }

    [Test]
    public async Task Signing_out_everywhere_else_keeps_the_named_session_and_ends_the_rest()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        var first = await harness.SignInAsync("pianonic", Password);
        var second = await harness.SignInAsync("pianonic", Password);
        var kept = await harness.SignInAsync("pianonic", Password);

        var revoked = await harness.Sessions.RevokeAllExceptAsync(user.Id, Family(kept, harness));

        await Assert.That(revoked).IsEqualTo(2);

        await Assert.That((await harness.SignIn.RefreshAsync(kept.Tokens!.RefreshToken)).Outcome)
            .IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That((await harness.SignIn.RefreshAsync(first.Tokens!.RefreshToken)).Outcome)
            .IsEqualTo(SignInOutcome.RefreshTokenRevoked);
        await Assert.That((await harness.SignIn.RefreshAsync(second.Tokens!.RefreshToken)).Outcome)
            .IsEqualTo(SignInOutcome.RefreshTokenRevoked);
    }

    [Test]
    public async Task Signing_out_everywhere_else_with_no_current_session_ends_every_one()
    {
        var harness = PasswordHarness.Create();
        var user = await RegisterAsync(harness);

        await harness.SignInAsync("pianonic", Password);
        await harness.SignInAsync("pianonic", Password);

        await Assert.That(await harness.Sessions.RevokeAllExceptAsync(user.Id, currentSessionId: null)).IsEqualTo(2);
        await Assert.That(await harness.Sessions.ListAsync(user.Id)).IsEmpty();
    }

    [Test]
    public async Task Another_user_s_sessions_are_left_alone_by_signing_out_everywhere_else()
    {
        var harness = PasswordHarness.Create();
        var ada = await RegisterAsync(harness);
        var grace = await RegisterAsync(harness, "grace", "grace@example.com");

        await harness.SignInAsync("pianonic", Password);
        await harness.SignInAsync("grace", Password);

        await harness.Sessions.RevokeAllExceptAsync(ada.Id, currentSessionId: null);

        await Assert.That(await harness.Sessions.ListAsync(grace.Id)).HasCount().EqualTo(1);
    }
}
