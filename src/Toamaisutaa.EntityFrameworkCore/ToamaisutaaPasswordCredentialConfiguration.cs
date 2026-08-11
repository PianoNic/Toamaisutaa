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

        // The user's own id is the key: one credential per account, enforced by the schema rather
        // than by a rule someone has to remember.
        builder.HasKey(credential => credential.UserId);
        builder.Property(credential => credential.UserId).ValueGeneratedNever();

        builder.Property(credential => credential.UserName).HasMaxLength(256).IsRequired();
        builder.Property(credential => credential.NormalizedUserName).HasMaxLength(256).IsRequired();
        builder.Property(credential => credential.Email).HasMaxLength(256);
        builder.Property(credential => credential.NormalizedEmail).HasMaxLength(256);
        builder.Property(credential => credential.PasswordHash).HasMaxLength(512).IsRequired();

        builder.Property(credential => credential.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.UpdatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.FirstFailedAttemptAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(credential => credential.LockedOutUntil).HasConversion(InstantConverters.NullableInstant);

        // Unique without a filter, which is the whole reason these live in their own table: only
        // accounts that sign in with a password have a row, so the constraint applies exactly where
        // it should and needs no provider-specific predicate.
        builder.HasIndex(credential => credential.NormalizedUserName).IsUnique();

        // Nullable and unique: both supported providers treat NULLs as distinct, so any number of
        // accounts may have no address while no two may share one.
        builder.HasIndex(credential => credential.NormalizedEmail).IsUnique();

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(credential => credential.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
