using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaEmailVerificationChallengeConfiguration : IEntityTypeConfiguration<ToamaisutaaEmailVerificationChallenge>
{
    public const string TableName = "ToamaisutaaEmailVerificationChallenges";

    public void Configure(EntityTypeBuilder<ToamaisutaaEmailVerificationChallenge> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(challenge => challenge.Id);
        builder.Property(challenge => challenge.Id).ValueGeneratedNever();

        builder.Property(challenge => challenge.TokenHash).HasMaxLength(64).IsRequired();

        // Matches the credential's email column, so any address that fits there fits here.
        builder.Property(challenge => challenge.NormalizedEmail).HasMaxLength(256).IsRequired();
        builder.Property(challenge => challenge.SecurityStamp).HasMaxLength(64);

        builder.Property(challenge => challenge.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(challenge => challenge.TokenHash).IsUnique();
        builder.HasIndex(challenge => challenge.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(challenge => challenge.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ToamaisutaaEmailVerificationCodeConfiguration : IEntityTypeConfiguration<ToamaisutaaEmailVerificationCode>
{
    public const string TableName = "ToamaisutaaEmailVerificationCodes";

    public void Configure(EntityTypeBuilder<ToamaisutaaEmailVerificationCode> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(code => code.Id);
        builder.Property(code => code.Id).ValueGeneratedNever();

        builder.Property(code => code.NormalizedEmail).HasMaxLength(256).IsRequired();
        builder.Property(code => code.CodeHash).HasMaxLength(64).IsRequired();

        builder.Property(code => code.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(code => code.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(code => code.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(code => code.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(code => code.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
