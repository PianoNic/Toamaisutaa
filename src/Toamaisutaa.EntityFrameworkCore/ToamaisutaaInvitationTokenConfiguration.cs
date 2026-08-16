using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaInvitationTokenConfiguration : IEntityTypeConfiguration<ToamaisutaaInvitationToken>
{
    public const string TableName = "ToamaisutaaInvitationTokens";

    public void Configure(EntityTypeBuilder<ToamaisutaaInvitationToken> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(token => token.Id);
        builder.Property(token => token.Id).ValueGeneratedNever();

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
