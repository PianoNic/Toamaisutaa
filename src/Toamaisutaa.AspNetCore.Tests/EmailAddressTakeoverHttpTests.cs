using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An account can ask for an address another account holds unproven, and redeeming the link moves it.
/// The mailbox's owner has to be told that is what the link does, and the account that lost it told it did.
/// </summary>
public class EmailAddressTakeoverHttpTests
{
    [Test]
    public async Task Asking_for_an_address_another_account_holds_unproven_warns_in_the_mail()
    {
        var sent = new List<(string Email, EmailVerificationContext Context)>();
        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IEmailVerificationNotifier>(new RecordingNotifier(sent)));

        var victim = await Account.RegisterAsync(app, "victim");
        var intruder = await Account.RegisterAsync(app, "intruder");

        await RequestAsync(app, intruder, victim.Email);

        await Assert.That(sent.Single().Context.TakesFromAnotherAccount).IsTrue();
    }

    [Test]
    public async Task A_free_address_or_one_s_own_does_not_warn()
    {
        var sent = new List<(string Email, EmailVerificationContext Context)>();
        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IEmailVerificationNotifier>(new RecordingNotifier(sent)));

        var account = await Account.RegisterAsync(app);

        await RequestAsync(app, account, account.Email);
        await RequestAsync(app, account, "somewhere.new@example.com");

        await Assert.That(sent.Select(entry => entry.Context.TakesFromAnotherAccount)).IsEquivalentTo(new[] { false, false });
    }

    [Test]
    public async Task The_account_that_loses_the_address_is_named_in_an_event()
    {
        var recorded = new List<AuthenticationEvent>();
        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var victim = await Account.RegisterAsync(app, "victim");
        var intruder = await Account.RegisterAsync(app, "intruder");

        await RequestAsync(app, intruder, victim.Email);
        await app.Client.PostJson("/auth/email/verify", new { token = app.IssuedEmailVerifications[^1].Token });

        var released = recorded.OfType<EmailAddressReleased>().Single();

        await Assert.That(released.UserId).IsEqualTo(Guid.Parse(victim.Claims().String("sub")!));
        await Assert.That(released.ClaimedByUserId).IsEqualTo(Guid.Parse(intruder.Claims().String("sub")!));
        await Assert.That(released.Email).IsEqualTo(victim.Email);
    }

    private static async Task RequestAsync(TestApp app, Account account, string newEmail)
    {
        var response = await app.Client.PostJson("/auth/email", new { newEmail, currentPassword = account.Password }, account.AccessToken);

        if (response.StatusCode != HttpStatusCode.NoContent)
            throw new InvalidOperationException($"Email change failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private sealed class RecordingNotifier(List<(string Email, EmailVerificationContext Context)> sent) : IEmailVerificationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("The package should call the overload that carries the context.");

        public Task SendAsync(
            ToamaisutaaUser user,
            string email,
            string verificationToken,
            EmailVerificationContext context,
            CancellationToken cancellationToken = default)
        {
            lock (sent)
                sent.Add((email, context));

            return Task.CompletedTask;
        }
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
