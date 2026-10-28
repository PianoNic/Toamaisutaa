using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>Public for the same reason as <see cref="ToamaisutaaUserConfiguration"/>.</summary>
public sealed class ToamaisutaaExternalLoginRequestConfiguration : IEntityTypeConfiguration<ToamaisutaaExternalLoginRequest>
{
    public const string TableName = "ToamaisutaaExternalLoginRequests";

    public void Configure(EntityTypeBuilder<ToamaisutaaExternalLoginRequest> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(request => request.Id);
        builder.Property(request => request.Id).ValueGeneratedNever();

        builder.Property(request => request.ProviderKey).HasMaxLength(128).IsRequired();
        builder.Property(request => request.StateHash).HasMaxLength(64).IsRequired();
        builder.Property(request => request.Nonce).HasMaxLength(64).IsRequired();
        builder.Property(request => request.CodeVerifier).HasMaxLength(128).IsRequired();
        builder.Property(request => request.RedirectUri).HasMaxLength(2048).IsRequired();
        builder.Property(request => request.ReturnUrl).HasMaxLength(2048).IsRequired();
        builder.Property(request => request.ClientState).HasMaxLength(512);
        builder.Property(request => request.ClientCodeChallenge).HasMaxLength(128);
        builder.Property(request => request.ExchangeCodeHash).HasMaxLength(64);
        builder.Property(request => request.SecurityStamp).HasMaxLength(64);

        builder.Property(request => request.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(request => request.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(request => request.ConsumedAt).HasConversion(InstantConverters.NullableInstant);
        builder.Property(request => request.ExchangeConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(request => request.StateHash).IsUnique();
        builder.HasIndex(request => request.ExchangeCodeHash).IsUnique();
        builder.HasIndex(request => request.ExpiresAt);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(request => request.LinkUserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
