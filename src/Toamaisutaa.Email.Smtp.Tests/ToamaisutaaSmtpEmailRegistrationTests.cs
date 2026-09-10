using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class ToamaisutaaSmtpEmailRegistrationTests
{
    private static ServiceCollection Services()
    {
        var services = new ServiceCollection();
        services.TryAddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddToamaisutaaSmtpEmail(options =>
        {
            options.Host = "smtp.example.com";
            options.From = "noreply@example.com";
            options.PasswordResetLinkTemplate = "https://app.example.com/reset?token={token}";
            options.InvitationLinkTemplate = "https://app.example.com/invite?token={token}";
        });

        return services;
    }

    // Registering an IInvitationNotifier or an IAdminPasswordIssuedNotifier is what maps
    // /auth/invitations and /auth/users at all. Installing this package for reset mail must not put
    // four endpoints on the wire that nobody asked for.
    [Test]
    public async Task TheResetRegistrationBringsNeitherOfTheOtherTwoNotifiers()
    {
        using var provider = Services().BuildServiceProvider();

        await Assert.That(provider.GetService<IPasswordResetNotifier>()).IsNotNull();
        await Assert.That(provider.GetService<IInvitationNotifier>()).IsNull();
        await Assert.That(provider.GetService<IAdminPasswordIssuedNotifier>()).IsNull();
    }

    [Test]
    public async Task InvitationEmailRegistersTheSmtpNotifier()
    {
        using var provider = Services().AddToamaisutaaSmtpInvitationEmail().BuildServiceProvider();

        await Assert.That(provider.GetService<IInvitationNotifier>()).IsTypeOf<SmtpInvitationNotifier>();
        await Assert.That(provider.GetService<IInvitationEmailTemplate>()).IsTypeOf<DefaultInvitationEmailTemplate>();
    }

    [Test]
    public async Task AdminPasswordEmailRegistersTheSmtpNotifier()
    {
        using var provider = Services().AddToamaisutaaSmtpAdminPasswordEmail().BuildServiceProvider();

        await Assert.That(provider.GetService<IAdminPasswordIssuedNotifier>()).IsTypeOf<SmtpAdminPasswordIssuedNotifier>();
        await Assert.That(provider.GetService<IAdminPasswordIssuedEmailTemplate>()).IsTypeOf<DefaultAdminPasswordIssuedEmailTemplate>();
    }

    [Test]
    public async Task AnInvitationNotifierTheConsumerRegisteredWins()
    {
        var services = Services();
        services.AddSingleton<IInvitationNotifier, FakeInvitationNotifier>();

        using var provider = services.AddToamaisutaaSmtpInvitationEmail().BuildServiceProvider();

        await Assert.That(provider.GetService<IInvitationNotifier>()).IsTypeOf<FakeInvitationNotifier>();
    }

    [Test]
    public async Task AnAdminPasswordNotifierTheConsumerRegisteredWins()
    {
        var services = Services();
        services.AddSingleton<IAdminPasswordIssuedNotifier, FakeAdminPasswordIssuedNotifier>();

        using var provider = services.AddToamaisutaaSmtpAdminPasswordEmail().BuildServiceProvider();

        await Assert.That(provider.GetService<IAdminPasswordIssuedNotifier>()).IsTypeOf<FakeAdminPasswordIssuedNotifier>();
    }

    [Test]
    public async Task AnInvitationTemplateTheConsumerRegisteredWins()
    {
        var services = Services();
        services.AddSingleton<IInvitationEmailTemplate, FakeInvitationEmailTemplate>();

        using var provider = services.AddToamaisutaaSmtpInvitationEmail().BuildServiceProvider();

        await Assert.That(provider.GetService<IInvitationEmailTemplate>()).IsTypeOf<FakeInvitationEmailTemplate>();
    }

    private sealed class FakeInvitationNotifier : IInvitationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeAdminPasswordIssuedNotifier : IAdminPasswordIssuedNotifier
    {
        public Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
