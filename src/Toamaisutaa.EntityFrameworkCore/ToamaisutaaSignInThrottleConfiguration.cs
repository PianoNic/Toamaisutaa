using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaSignInThrottleConfiguration : IEntityTypeConfiguration<ToamaisutaaSignInThrottle>
{
    public const string TableName = "ToamaisutaaSignInThrottles";

    public void Configure(EntityTypeBuilder<ToamaisutaaSignInThrottle> builder)
    {
        builder.ToTable(TableName);

        // The key is what makes concurrent first failures from one source collide instead of
        // inserting two rows that each count one.
        builder.HasKey(row => new { row.UserId, row.Source });

        builder.Property(row => row.Source).HasMaxLength(64).IsRequired();

        builder.Property(row => row.FirstFailedAttemptAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(row => row.LockedOutUntil).HasConversion(InstantConverters.NullableInstant);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(row => row.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
