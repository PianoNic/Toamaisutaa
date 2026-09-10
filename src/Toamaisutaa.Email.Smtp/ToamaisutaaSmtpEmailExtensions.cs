using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Email.Smtp;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaSmtpEmailExtensions
{
    private const string ConfigurationSection = "Email:Smtp";

    /// <summary>
    /// Registers an SMTP-backed <see cref="IPasswordResetNotifier"/>, so password reset actually
    /// sends mail without you writing a notifier. Optional - local password login works with any
    /// <see cref="IPasswordResetNotifier"/>, including one you write yourself.
    /// </summary>
    /// <remarks>
    /// Host, port, sender address and <see cref="ToamaisutaaSmtpEmailOptions.PasswordResetLinkTemplate"/>
    /// are checked at startup rather than at the first password reset request. Register your own
    /// <see cref="IPasswordResetEmailTemplate"/> before calling this to replace the default wording.
    /// <para>
    /// The reset email and nothing else. Invitations and admin-issued passwords are opt-in one at a
    /// time - see <see cref="AddToamaisutaaSmtpInvitationEmail"/> and
    /// <see cref="AddToamaisutaaSmtpAdminPasswordEmail"/>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddToamaisutaaSmtpEmail(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaSmtpEmailOptions>().Bind(configuration.GetSection(sectionName));

        return AddSmtpEmailCore(services);
    }

    public static IServiceCollection AddToamaisutaaSmtpEmail(
        this IServiceCollection services,
        Action<ToamaisutaaSmtpEmailOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<ToamaisutaaSmtpEmailOptions>();
        services.Configure(configure);

        return AddSmtpEmailCore(services);
    }

    /// <summary>
    /// Adds an SMTP-backed <see cref="IInvitationNotifier"/> on top of
    /// <see cref="AddToamaisutaaSmtpEmail(IServiceCollection, IConfiguration, string)"/>, which
    /// binds the options and the transport this uses and has to be called as well.
    /// </summary>
    /// <remarks>
    /// Separate from the call above, and not part of it, because registering an
    /// <see cref="IInvitationNotifier"/> is what maps <c>POST /auth/invitations</c> and
    /// <c>POST /auth/invitations/complete</c> at all. An application that installed this package to
    /// send reset mail should not find two endpoints it never asked for on the wire.
    /// <para>
    /// <see cref="ToamaisutaaSmtpEmailOptions.InvitationLinkTemplate"/> is checked at startup unless
    /// you register your own <see cref="IInvitationEmailTemplate"/>, which replaces the wording and
    /// the link both.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddToamaisutaaSmtpInvitationEmail(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IInvitationEmailTemplate, DefaultInvitationEmailTemplate>();
        services.TryAddSingleton<IInvitationNotifier, SmtpInvitationNotifier>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SmtpInvitationStartupCheck>());

        return services;
    }

    /// <summary>
    /// Adds an SMTP-backed <see cref="IAdminPasswordIssuedNotifier"/> on top of
    /// <see cref="AddToamaisutaaSmtpEmail(IServiceCollection, IConfiguration, string)"/>, which
    /// binds the options and the transport this uses and has to be called as well.
    /// </summary>
    /// <remarks>
    /// Separate for the same reason as the invitation notifier: registering one is what maps
    /// <c>POST /auth/users</c> and <c>POST /auth/users/{userId}/password</c> at all.
    /// <para>
    /// Emailing a password is emailing a credential, and it stays valid until somebody changes it.
    /// The default wording says to change it straight away; if that is not good enough for you,
    /// register your own <see cref="IAdminPasswordIssuedEmailTemplate"/>, or your own
    /// <see cref="IAdminPasswordIssuedNotifier"/> and do not send mail at all.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddToamaisutaaSmtpAdminPasswordEmail(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IAdminPasswordIssuedEmailTemplate, DefaultAdminPasswordIssuedEmailTemplate>();
        services.TryAddSingleton<IAdminPasswordIssuedNotifier, SmtpAdminPasswordIssuedNotifier>();

        return services;
    }

    private static IServiceCollection AddSmtpEmailCore(IServiceCollection services)
    {
        services.TryAddSingleton<IPasswordResetEmailTemplate, DefaultPasswordResetEmailTemplate>();
        services.TryAddSingleton<ISmtpMessageSender, MailKitSmtpMessageSender>();
        services.TryAddSingleton<IPasswordResetNotifier, SmtpPasswordResetNotifier>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SmtpEmailStartupCheck>());

        return services;
    }
}
