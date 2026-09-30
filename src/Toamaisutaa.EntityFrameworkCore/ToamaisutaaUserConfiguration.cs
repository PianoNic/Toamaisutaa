using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>Public so consumers who keep the tables in their own context can apply it
/// themselves, and call <c>ToTable</c> after it if they want different names.</summary>
public sealed class ToamaisutaaUserConfiguration : IEntityTypeConfiguration<ToamaisutaaUser>
{
    public const string TableName = "ToamaisutaaUsers";

    public void Configure(EntityTypeBuilder<ToamaisutaaUser> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(user => user.Id);

        builder.Property(user => user.Id).ValueGeneratedNever();

        builder.Property(user => user.UserName).HasMaxLength(256);
        builder.Property(user => user.Email).HasMaxLength(256);
        builder.Property(user => user.DisplayName).HasMaxLength(256);
        builder.Property(user => user.PictureUrl).HasMaxLength(2048);
        builder.Property(user => user.SecurityStamp).HasMaxLength(128).IsRequired();

        builder.Property(user => user.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(user => user.UpdatedAt).HasConversion(InstantConverters.Instant);

        // Deliberately not unique: one person at two identity providers is two rows sharing an
        // address. Local login's unique email lives on ToamaisutaaPasswordCredentials.
        builder.HasIndex(user => user.Email);
    }
}
