using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Carries the Toamaisutaa tables on its own, for consumers who would rather not touch their
/// existing context. The alternative is <see cref="ToamaisutaaModelBuilderExtensions.ApplyToamaisutaaConfiguration"/>
/// inside a context you already have.
/// </summary>
public class ToamaisutaaDbContext : DbContext
{
    public ToamaisutaaDbContext(DbContextOptions<ToamaisutaaDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// For a derived context. Entity Framework hands a subclass its own
    /// <c>DbContextOptions&lt;TDerived&gt;</c>, which the constructor above cannot accept.
    /// Protected rather than public so it does not compete for constructor selection when this
    /// context is registered directly.
    /// </summary>
    protected ToamaisutaaDbContext(DbContextOptions options)
        : base(options)
    {
    }

    public DbSet<ToamaisutaaUser> Users => Set<ToamaisutaaUser>();

    public DbSet<ToamaisutaaExternalLogin> ExternalLogins => Set<ToamaisutaaExternalLogin>();

    public DbSet<ToamaisutaaPasswordCredential> PasswordCredentials => Set<ToamaisutaaPasswordCredential>();

    public DbSet<ToamaisutaaRefreshToken> RefreshTokens => Set<ToamaisutaaRefreshToken>();

    public DbSet<ToamaisutaaPasswordResetToken> PasswordResetTokens => Set<ToamaisutaaPasswordResetToken>();

    public DbSet<ToamaisutaaInvitationToken> InvitationTokens => Set<ToamaisutaaInvitationToken>();

    public DbSet<ToamaisutaaUserTwoFactor> UserTwoFactors => Set<ToamaisutaaUserTwoFactor>();

    public DbSet<ToamaisutaaRecoveryCode> RecoveryCodes => Set<ToamaisutaaRecoveryCode>();

    public DbSet<ToamaisutaaTwoFactorChallenge> TwoFactorChallenges => Set<ToamaisutaaTwoFactorChallenge>();

    public DbSet<ToamaisutaaTrustedDevice> TrustedDevices => Set<ToamaisutaaTrustedDevice>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyToamaisutaaConfiguration();
    }
}
