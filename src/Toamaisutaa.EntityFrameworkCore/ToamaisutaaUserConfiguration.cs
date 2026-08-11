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

        // The store assigns a UUIDv7, so the two providers behave identically and a user and its
        // external login can be inserted in one round trip.
        builder.Property(user => user.Id).ValueGeneratedNever();

        builder.Property(user => user.UserName).HasMaxLength(256);
        builder.Property(user => user.Email).HasMaxLength(256);
        builder.Property(user => user.DisplayName).HasMaxLength(256);
        builder.Property(user => user.PictureUrl).HasMaxLength(2048);

        // Not unique: an email is a lookup key here, never an identity. Linking is by subject.
        builder.HasIndex(user => user.Email);
    }
}
