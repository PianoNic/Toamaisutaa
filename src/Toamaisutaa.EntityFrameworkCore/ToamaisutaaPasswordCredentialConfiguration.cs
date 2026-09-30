using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaPasswordCredentialConfiguration : IEntityTypeConfiguration<ToamaisutaaPasswordCredential>
{
    public const string TableName = "ToamaisutaaPasswordCredentials";

    public void Configure(EntityTypeBuilder<ToamaisutaaPasswordCredential> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(credential => credential.UserId);
        builder.Property(credential => credential.UserId).ValueGeneratedNever();

        builder.Property(credential => credential.UserName).HasMaxLength(256).IsRequired();
        builder.Property(credential => credential.NormalizedUserName).HasMaxLength(256).IsRequired();
        builder.Property(credential => credential.Email).HasMaxLength(256);
        builder.Property(credential => credential.NormalizedEmail).HasMaxLength(256);
        builder.Property(credential => credential.PasswordHash).HasMaxLength(512).IsRequired();

        builder.Property(credential => credential.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.UpdatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.EmailConfirmedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(credential => credential.FirstFailedAttemptAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(credential => credential.LockedOutUntil).HasConversion(InstantConverters.NullableInstant);

        // Every column two requests can race on, so a stale write fails rather than restoring an old
        // hash or undercounting parallel wrong passwords.
        builder.Property(credential => credential.PasswordHash).IsConcurrencyToken();
        builder.Property(credential => credential.NormalizedEmail).IsConcurrencyToken();
        builder.Property(credential => credential.FailedAttemptCount).IsConcurrencyToken();
        builder.Property(credential => credential.LockedOutUntil).IsConcurrencyToken();

        // A window restart at a count of one writes the same count back, so without this a burst of
        // stale reservations all match and all get checked.
        builder.Property(credential => credential.FirstFailedAttemptAt).IsConcurrencyToken();

        builder.HasIndex(credential => credential.NormalizedUserName).IsUnique();

        // Nullable and unique relies on the providers treating NULLs as distinct.
        builder.HasIndex(credential => credential.NormalizedEmail).IsUnique();

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(credential => credential.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
