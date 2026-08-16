using Microsoft.EntityFrameworkCore;

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
        modelBuilder.ApplyConfiguration(new ToamaisutaaUserTwoFactorConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaRecoveryCodeConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaTwoFactorChallengeConfiguration());
        modelBuilder.ApplyConfiguration(new ToamaisutaaTrustedDeviceConfiguration());

        return modelBuilder;
    }
}
