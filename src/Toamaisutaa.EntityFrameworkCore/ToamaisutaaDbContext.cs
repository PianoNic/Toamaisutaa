using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Carries the Toamaisutaa tables on its own, for consumers who would rather not touch their
/// existing context. The alternative is <see cref="ToamaisutaaModelBuilderExtensions.ApplyToamaisutaaConfiguration"/>
/// inside a context you already have.
/// </summary>
public class ToamaisutaaDbContext(DbContextOptions<ToamaisutaaDbContext> options) : DbContext(options)
{
    public DbSet<ToamaisutaaUser> Users => Set<ToamaisutaaUser>();

    public DbSet<ToamaisutaaExternalLogin> ExternalLogins => Set<ToamaisutaaExternalLogin>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyToamaisutaaConfiguration();
    }
}
