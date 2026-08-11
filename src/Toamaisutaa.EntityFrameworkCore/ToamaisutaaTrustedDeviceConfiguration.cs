using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaTrustedDeviceConfiguration : IEntityTypeConfiguration<ToamaisutaaTrustedDevice>
{
    public const string TableName = "ToamaisutaaTrustedDevices";

    public void Configure(EntityTypeBuilder<ToamaisutaaTrustedDevice> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(device => device.Id);
        builder.Property(device => device.Id).ValueGeneratedNever();

        builder.Property(device => device.TokenHash).HasMaxLength(64).IsRequired();
        builder.Property(device => device.SecurityStamp).HasMaxLength(128).IsRequired();
        builder.Property(device => device.Label).HasMaxLength(128);
        builder.Property(device => device.UserAgent).HasMaxLength(256);

        // Sized for an IPv6 address plus a prefix suffix. Null unless TrustedDevices:IpAddressStorage
        // says otherwise, which is the default.
        builder.Property(device => device.IpAddress).HasMaxLength(64);

        builder.Property(device => device.RevokedReason).HasMaxLength(64);

        builder.Property(device => device.SecondFactorAt).HasConversion(InstantConverters.Instant);
        builder.Property(device => device.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(device => device.FamilyStartedAt).HasConversion(InstantConverters.Instant);
        builder.Property(device => device.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(device => device.LastUsedAt).HasConversion(InstantConverters.Instant);
        builder.Property(device => device.RotatedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(device => device.RevokedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(device => device.TokenHash).IsUnique();

        // Every sign-in looks one up by hash; listing and revoking work by family and by user.
        builder.HasIndex(device => device.FamilyId);
        builder.HasIndex(device => device.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(device => device.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
