using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaRefreshTokenConfiguration : IEntityTypeConfiguration<ToamaisutaaRefreshToken>
{
    public const string TableName = "ToamaisutaaRefreshTokens";

    public void Configure(EntityTypeBuilder<ToamaisutaaRefreshToken> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(token => token.Id);
        builder.Property(token => token.Id).ValueGeneratedNever();

        builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();
        builder.Property(token => token.RevokedReason).HasMaxLength(64);
        builder.Property(token => token.SecurityStamp).HasMaxLength(128).IsRequired();

        builder.Property(token => token.AuthenticationMethods).HasMaxLength(128).IsRequired();
        builder.Property(token => token.TwoFactorSource).HasMaxLength(32);
        builder.Property(token => token.UserAgent).HasMaxLength(256);

        builder.Property(token => token.IpAddress).HasMaxLength(64);

        builder.Property(token => token.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.FamilyStartedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.LastUsedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.RotatedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(token => token.RevokedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(token => token.SecondFactorAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(token => token.TokenHash).IsUnique();

        builder.HasIndex(token => token.FamilyId);
        builder.HasIndex(token => token.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(token => token.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
