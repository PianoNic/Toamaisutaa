using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaUserTwoFactorConfiguration : IEntityTypeConfiguration<ToamaisutaaUserTwoFactor>
{
    public const string TableName = "ToamaisutaaUserTwoFactors";

    public void Configure(EntityTypeBuilder<ToamaisutaaUserTwoFactor> builder)
    {
        builder.ToTable(TableName);

        // The user id is the key. One enrolment per account, enforced by the schema rather than by
        // remembering to check.
        builder.HasKey(enrolment => enrolment.UserId);
        builder.Property(enrolment => enrolment.UserId).ValueGeneratedNever();

        // 20 bytes of secret plus AES-GCM's fixed overhead. Sized generously because
        // SecretSizeBytes is configurable and a column limit is a poor way to discover that.
        builder.Property(enrolment => enrolment.SecretCiphertext).HasMaxLength(256).IsRequired();
        builder.Property(enrolment => enrolment.SecretNonce).HasMaxLength(32).IsRequired();
        builder.Property(enrolment => enrolment.SecretTag).HasMaxLength(32).IsRequired();
        builder.Property(enrolment => enrolment.EncryptionKeyVersion).HasMaxLength(64).IsRequired();

        builder.Property(enrolment => enrolment.ConfirmedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(enrolment => enrolment.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(enrolment => enrolment.UpdatedAt).HasConversion(InstantConverters.Instant);

        builder.Ignore(enrolment => enrolment.IsEnabled);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(enrolment => enrolment.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ToamaisutaaRecoveryCodeConfiguration : IEntityTypeConfiguration<ToamaisutaaRecoveryCode>
{
    public const string TableName = "ToamaisutaaRecoveryCodes";

    public void Configure(EntityTypeBuilder<ToamaisutaaRecoveryCode> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(code => code.Id);
        builder.Property(code => code.Id).ValueGeneratedNever();

        builder.Property(code => code.CodeHash).HasMaxLength(64).IsRequired();

        builder.Property(code => code.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(code => code.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        // Redemption looks up one user's codes by hash. Not unique on the hash alone: two accounts
        // colliding on a fifty-bit code is not going to happen, but a unique index would turn it
        // into somebody else's failed login rather than a shrug.
        builder.HasIndex(code => new { code.UserId, code.CodeHash });

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(code => code.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ToamaisutaaTwoFactorChallengeConfiguration : IEntityTypeConfiguration<ToamaisutaaTwoFactorChallenge>
{
    public const string TableName = "ToamaisutaaTwoFactorChallenges";

    public void Configure(EntityTypeBuilder<ToamaisutaaTwoFactorChallenge> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(challenge => challenge.Id);
        builder.Property(challenge => challenge.Id).ValueGeneratedNever();

        builder.Property(challenge => challenge.TokenHash).HasMaxLength(64).IsRequired();

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
