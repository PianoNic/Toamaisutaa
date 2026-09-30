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
    /// Registers an SMTP-backed <see cref="IPasswordResetNotifier"/> and the transport the other SMTP
    /// notifiers use.
    /// </summary>
    /// <remarks>
    /// Host, port, sender address and <see cref="ToamaisutaaSmtpEmailOptions.PasswordResetLinkTemplate"/>
    /// are checked at startup. Register your own <see cref="IPasswordResetEmailTemplate"/> before
    /// calling this to replace the default wording. The other emails are opt-in one at a time.
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
    /// Separate because registering an <see cref="IInvitationNotifier"/> is what maps
    /// <c>POST /auth/invitations</c> and <c>POST /auth/invitations/complete</c> at all.
    /// <see cref="ToamaisutaaSmtpEmailOptions.InvitationLinkTemplate"/> is checked at startup unless
    /// you register your own <see cref="IInvitationEmailTemplate"/>.
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
    /// Adds an SMTP-backed <see cref="IEmailVerificationNotifier"/> on top of
    /// <see cref="AddToamaisutaaSmtpEmail(IServiceCollection, IConfiguration, string)"/>, which
    /// binds the options and the transport this uses and has to be called as well.
    /// </summary>
    /// <remarks>
    /// Separate because registering one is what maps <c>POST /auth/email</c> and
    /// <c>POST /auth/email/verify</c> at all.
    /// <see cref="ToamaisutaaSmtpEmailOptions.EmailVerificationLinkTemplate"/> is checked at startup
    /// unless you register your own <see cref="IEmailVerificationEmailTemplate"/>.
    /// </remarks>
    public static IServiceCollection AddToamaisutaaSmtpEmailVerification(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IEmailVerificationEmailTemplate, DefaultEmailVerificationEmailTemplate>();
        services.TryAddSingleton<IEmailVerificationNotifier, SmtpEmailVerificationNotifier>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SmtpEmailVerificationStartupCheck>());

        return services;
    }

    /// <summary>
    /// Adds an SMTP-backed <see cref="IMagicLinkNotifier"/> on top of
    /// <see cref="AddToamaisutaaSmtpEmail(IServiceCollection, IConfiguration, string)"/>, which
    /// binds the options and the transport this uses and has to be called as well.
    /// </summary>
    /// <remarks>
    /// Separate because registering one is what maps <c>POST /auth/magic-link</c> and
    /// <c>POST /auth/magic-link/verify</c> at all.
    /// <para>
    /// A magic link is only sent to a verified address, so an <see cref="IEmailVerificationNotifier"/>
    /// (such as <see cref="AddToamaisutaaSmtpEmailVerification"/>) must be registered too; startup
    /// refuses the pair without it.
    /// </para>
    /// <para>
    /// <see cref="ToamaisutaaSmtpEmailOptions.MagicLinkTemplate"/> is checked at startup unless you
    /// register your own <see cref="IMagicLinkEmailTemplate"/>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddToamaisutaaSmtpMagicLink(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IMagicLinkEmailTemplate, DefaultMagicLinkEmailTemplate>();
        services.TryAddSingleton<IMagicLinkNotifier, SmtpMagicLinkNotifier>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SmtpMagicLinkStartupCheck>());

        return services;
    }

    /// <summary>
    /// Adds an SMTP-backed <see cref="IAdminPasswordIssuedNotifier"/> on top of
    /// <see cref="AddToamaisutaaSmtpEmail(IServiceCollection, IConfiguration, string)"/>, which
    /// binds the options and the transport this uses and has to be called as well.
    /// </summary>
    /// <remarks>
    /// Separate because registering one is what maps <c>POST /auth/users</c> and
    /// <c>POST /auth/users/{userId}/password</c> at all.
    /// <para>
    /// Emailing a password is emailing a credential that stays valid until somebody changes it; to
    /// avoid that, register your own <see cref="IAdminPasswordIssuedNotifier"/> instead.
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
