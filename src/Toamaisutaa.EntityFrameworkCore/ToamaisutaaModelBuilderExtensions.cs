using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public static class ToamaisutaaModelBuilderExtensions
{
    /// <summary>
    /// Adds the Toamaisutaa tables to a consumer's own <c>DbContext</c>. Call it from
    /// <c>OnModelCreating</c> and generate the migration in your own project; the migration
    /// assemblies this package ships only cover <see cref="ToamaisutaaDbContext"/>.
    /// </summary>
    public static ModelBuilder ApplyToamaisutaaConfiguration(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.ApplyConfiguration(new ToamaisutaaUserConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaExternalLoginConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaPasswordCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaRefreshTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaPasswordResetTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaInvitationTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaEmailVerificationTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaMagicLinkTokenConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaUserTwoFactorConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaRecoveryCodeConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaTwoFactorChallengeConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaTrustedDeviceConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaPasskeyCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaPasskeyChallengeConfiguration());

        return modelBuilder;
    }

    /// <summary>
    /// The same, plus what depends on the database the model is built for: an exact collation on
    /// <c>ToamaisutaaExternalLogins.Subject</c> on SQL Server and MySQL. Pass the context's
    /// <c>Database</c>.
    /// </summary>
    /// <remarks>
    /// An OpenID Connect subject is case-sensitive, and the default collations on those two are not -
    /// MySQL's ignores accents too - so the unique index on provider and subject treated <c>alice</c>
    /// and <c>ALICE</c> as one subject, and the second could never be provisioned. PostgreSQL and
    /// SQLite already compare exactly, and are left alone.
    /// </remarks>
    public static ModelBuilder ApplyToamaisutaaConfiguration(this ModelBuilder modelBuilder, DatabaseFacade database)
    {
        ArgumentNullException.ThrowIfNull(database);

        modelBuilder.ApplyToamaisutaaConfiguration();

        var exact = database.ProviderName switch
        {
            "Microsoft.EntityFrameworkCore.SqlServer" => "Latin1_General_100_BIN2",
            "MySql.EntityFrameworkCore" or "Pomelo.EntityFrameworkCore.MySql" => "utf8mb4_bin",
            _ => null,
        };

        if (exact is not null)
            modelBuilder.Entity<ToamaisutaaExternalLogin>().Property(login => login.Subject).UseCollation(exact);

        return modelBuilder;
    }
}
