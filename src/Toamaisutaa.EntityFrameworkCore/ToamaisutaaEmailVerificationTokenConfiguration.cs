using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaEmailVerificationTokenConfiguration : IEntityTypeConfiguration<ToamaisutaaEmailVerificationToken>
{
    public const string TableName = "ToamaisutaaEmailVerificationTokens";

    public void Configure(EntityTypeBuilder<ToamaisutaaEmailVerificationToken> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(token => token.Id);
        builder.Property(token => token.Id).ValueGeneratedNever();

        // Matches the credential's email column, so any address that fits there fits here.
        builder.Property(token => token.Email).HasMaxLength(256).IsRequired();

        builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();

        builder.Property(token => token.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(token => token.TokenHash).IsUnique();
        builder.HasIndex(token => token.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(token => token.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
