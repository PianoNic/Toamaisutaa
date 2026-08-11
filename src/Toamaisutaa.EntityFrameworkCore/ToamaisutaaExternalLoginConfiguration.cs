using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>Public for the same reason as <see cref="ToamaisutaaUserConfiguration"/>.</summary>
public sealed class ToamaisutaaExternalLoginConfiguration : IEntityTypeConfiguration<ToamaisutaaExternalLogin>
{
    public const string TableName = "ToamaisutaaExternalLogins";

    public void Configure(EntityTypeBuilder<ToamaisutaaExternalLogin> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(login => login.Id);

        builder.Property(login => login.Id).ValueGeneratedNever();

        builder.Property(login => login.ProviderKey).HasMaxLength(128).IsRequired();
        builder.Property(login => login.Subject).HasMaxLength(256).IsRequired();
        builder.Property(login => login.Issuer).HasMaxLength(512);

        // The identity constraint of the whole package: one subject per provider, once. It is also
        // what makes a concurrent first sign-in fail loudly instead of creating two users.
        builder.HasIndex(login => new { login.ProviderKey, login.Subject }).IsUnique();

        // Configured from this side because ToamaisutaaUser deliberately has no navigation property.
        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(login => login.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
