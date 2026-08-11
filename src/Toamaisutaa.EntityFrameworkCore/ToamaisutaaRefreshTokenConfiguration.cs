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

        // Base64 of a SHA-256 is 44 characters; the column is sized for it and nothing else, since
        // the raw token is never stored.
        builder.Property(token => token.TokenHash).HasMaxLength(64).IsRequired();
        builder.Property(token => token.RevokedReason).HasMaxLength(64);

        // Expiry is range-queried by the cleanup sweep, which is exactly the comparison SQLite
        // cannot translate on a timestamp column.
        builder.Property(token => token.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.FamilyStartedAt).HasConversion(InstantConverters.Instant);
        builder.Property(token => token.RotatedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(token => token.RevokedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(token => token.TokenHash).IsUnique();

        // Every refresh looks a token up by hash; every reuse revokes by family.
        builder.HasIndex(token => token.FamilyId);
        builder.HasIndex(token => token.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(token => token.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
