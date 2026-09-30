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

        builder.HasKey(enrolment => enrolment.UserId);
        builder.Property(enrolment => enrolment.UserId).ValueGeneratedNever();

        // Defaulted so rows written before the column existed read as zero.
        builder.Property(enrolment => enrolment.FailedAttemptCount).HasDefaultValue(0);
        builder.Property(enrolment => enrolment.FirstFailedAttemptAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(enrolment => enrolment.LockedOutUntil).HasConversion(InstantConverters.NullableInstant);

        // Sized generously because SecretSizeBytes is configurable.
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

        // Not unique: a cross-account hash collision must not become somebody else's failed login.
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

        builder.Property(challenge => challenge.Purpose).IsRequired();

        // No foreign key: families are a column on the refresh token, not a table.
        builder.Property(challenge => challenge.FamilyId);

        builder.Property(challenge => challenge.AuthenticationMethods).HasMaxLength(128).IsRequired();

        // Nullable so rows written before the column existed stay readable; they expire in minutes.
        builder.Property(challenge => challenge.SecurityStamp).HasMaxLength(128);

        builder.HasIndex(challenge => challenge.TokenHash).IsUnique();
        builder.HasIndex(challenge => challenge.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(challenge => challenge.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
