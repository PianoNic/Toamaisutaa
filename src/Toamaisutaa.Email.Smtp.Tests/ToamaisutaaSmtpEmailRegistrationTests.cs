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
            options.EmailVerificationLinkTemplate = "https://app.example.com/verify?token={token}";
            options.MagicLinkTemplate = "https://app.example.com/signin?token={token}";
        });

        return services;
    }

    // Registering an IInvitationNotifier, an IEmailVerificationNotifier or an
    // IAdminPasswordIssuedNotifier is what maps /auth/invitations, /auth/email and /auth/users at
    // all. Installing this package for reset mail must not put six endpoints on the wire that
    // nobody asked for.
    [Test]
    public async Task TheResetRegistrationBringsNoneOfTheOtherThreeNotifiers()
    {
        using var provider = Services().BuildServiceProvider();

        await Assert.That(provider.GetService<IPasswordResetNotifier>()).IsNotNull();
        await Assert.That(provider.GetService<IInvitationNotifier>()).IsNull();
        await Assert.That(provider.GetService<IEmailVerificationNotifier>()).IsNull();
        await Assert.That(provider.GetService<IMagicLinkNotifier>()).IsNull();
        await Assert.That(provider.GetService<IAdminPasswordIssuedNotifier>()).IsNull();
    }

    [Test]
    public async Task MagicLinkRegistersTheSmtpNotifier()
    {
        using var provider = Services().AddToamaisutaaSmtpMagicLink().BuildServiceProvider();

        await Assert.That(provider.GetService<IMagicLinkNotifier>()).IsTypeOf<SmtpMagicLinkNotifier>();
        await Assert.That(provider.GetService<IMagicLinkEmailTemplate>()).IsTypeOf<DefaultMagicLinkEmailTemplate>();
    }

    [Test]
    public async Task AMagicLinkNotifierTheConsumerRegisteredWins()
    {
        var services = Services();
        services.AddSingleton<IMagicLinkNotifier, FakeMagicLinkNotifier>();

        using var provider = services.AddToamaisutaaSmtpMagicLink().BuildServiceProvider();

        await Assert.That(provider.GetService<IMagicLinkNotifier>()).IsTypeOf<FakeMagicLinkNotifier>();
    }

    [Test]
    public async Task EmailVerificationRegistersTheSmtpNotifier()
    {
        using var provider = Services().AddToamaisutaaSmtpEmailVerification().BuildServiceProvider();

        await Assert.That(provider.GetService<IEmailVerificationNotifier>()).IsTypeOf<SmtpEmailVerificationNotifier>();
        await Assert.That(provider.GetService<IEmailVerificationEmailTemplate>()).IsTypeOf<DefaultEmailVerificationEmailTemplate>();
    }

    [Test]
    public async Task AnEmailVerificationNotifierTheConsumerRegisteredWins()
    {
        var services = Services();
        services.AddSingleton<IEmailVerificationNotifier, FakeEmailVerificationNotifier>();

        using var provider = services.AddToamaisutaaSmtpEmailVerification().BuildServiceProvider();

        await Assert.That(provider.GetService<IEmailVerificationNotifier>()).IsTypeOf<FakeEmailVerificationNotifier>();
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

    private sealed class FakeEmailVerificationNotifier : IEmailVerificationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeMagicLinkNotifier : IMagicLinkNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeAdminPasswordIssuedNotifier : IAdminPasswordIssuedNotifier
    {
        public Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
