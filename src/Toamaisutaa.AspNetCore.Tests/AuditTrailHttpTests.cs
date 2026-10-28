using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Who did what: the operations that used to publish nothing, and the actor on every event.</summary>
public class AuditTrailHttpTests
{
    [Test]
    public async Task An_administrator_s_actions_name_the_administrator()
    {
        var recorded = new List<AuthenticationEvent>();
        await using var app = await StartAsync(recorded);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);
        var adminSubject = admin.Claims().String("sub");

        var created = await app.Client.PostJson("/auth/users", new { userName = "pupil", email = "pupil@example.com", password = "a chosen password" }, admin.AccessToken);
        var pupilId = Guid.Parse((await created.Json()).String("userId")!);
        await app.Client.PostEmpty($"/auth/users/{pupilId}/disable", admin.AccessToken);

        var creation = Events<AccountCreated>(recorded).Single(found => found.UserId == pupilId);
        var disabling = Events<AccountDisabled>(recorded).Single();

        await Assert.That(creation.Source).IsEqualTo("administrator");
        await Assert.That(creation.ActorSubject).IsEqualTo(adminSubject);
        await Assert.That(disabling.UserId).IsEqualTo(pupilId);
        await Assert.That(disabling.ActorSubject).IsEqualTo(adminSubject);
    }

    [Test]
    public async Task A_registration_is_an_account_created_by_nobody_signed_in()
    {
        var recorded = new List<AuthenticationEvent>();
        await using var app = await StartAsync(recorded);

        var account = await Account.RegisterAsync(app);

        var creation = Events<AccountCreated>(recorded).Single();

        await Assert.That(creation.Source).IsEqualTo("registration");
        await Assert.That(creation.UserId).IsEqualTo(Guid.Parse(account.Claims().String("sub")!));
        await Assert.That(creation.ActorSubject).IsNull();
    }

    [Test]
    public async Task Invitations_publish_when_sent_and_when_completed()
    {
        var recorded = new List<AuthenticationEvent>();
        await using var app = await StartAsync(recorded);
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        await app.Client.PostJson("/auth/invitations", new { email = "invited@example.com" }, admin.AccessToken);
        var (userId, token) = app.IssuedInvitations.Single();
        await app.Client.PostJson("/auth/invitations/complete", new { token, userName = "invited", password = Account.DefaultPassword });

        await Assert.That(Events<InvitationSent>(recorded).Single().Email).IsEqualTo("invited@example.com");
        await Assert.That(Events<AccountCreated>(recorded).Single(found => found.UserId == userId).Source).IsEqualTo("invitation");
    }

    [Test]
    public async Task Mailed_links_publish_when_they_are_issued()
    {
        var recorded = new List<AuthenticationEvent>();
        var resets = new List<string>();
        await using var app = await StartAsync(recorded, services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets)));
        var account = await Account.RegisterAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await account.VerifyEmailAsync();
        await account.RequestMagicLinkAsync();
        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });

        await Assert.That(Events<EmailChangeRequested>(recorded).Single().Email).IsEqualTo(account.Email);
        await Assert.That(Events<MagicLinkRequested>(recorded).Single().UserId).IsEqualTo(userId);
        await Assert.That(Events<PasswordResetRequested>(recorded).Single().UserId).IsEqualTo(userId);
    }

    private static Task<TestApp> StartAsync(List<AuthenticationEvent> recorded, Action<IServiceCollection>? more = null) =>
        TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
            more?.Invoke(services);
        });

    private static List<T> Events<T>(List<AuthenticationEvent> recorded)
    {
        lock (recorded)
            return [.. recorded.OfType<T>()];
    }

    private sealed class RecordingSink(List<AuthenticationEvent> recorded) : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
        {
            lock (recorded)
                recorded.Add(authenticationEvent);

            return Task.CompletedTask;
        }
    }
}
