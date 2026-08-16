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

    private static IServiceCollection AddSmtpEmailCore(IServiceCollection services)
    {
        services.TryAddSingleton<IPasswordResetEmailTemplate, DefaultPasswordResetEmailTemplate>();
        services.TryAddSingleton<ISmtpMessageSender, MailKitSmtpMessageSender>();
        services.TryAddSingleton<IPasswordResetNotifier, SmtpPasswordResetNotifier>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SmtpEmailStartupCheck>());

        return services;
    }
}
