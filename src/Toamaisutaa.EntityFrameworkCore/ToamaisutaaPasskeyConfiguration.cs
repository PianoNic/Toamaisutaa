using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaPasskeyCredentialConfiguration : IEntityTypeConfiguration<ToamaisutaaPasskeyCredential>
{
    public const string TableName = "ToamaisutaaPasskeyCredentials";

    /// <summary>
    /// What the credential id column holds at most. WebAuthn allows up to 1023 bytes, but the column
    /// is uniquely indexed and MySQL's InnoDB caps an index key at 3072 bytes; longer ids are refused
    /// at registration.
    /// </summary>
    public const int CredentialIdLength = 256;

    public void Configure(EntityTypeBuilder<ToamaisutaaPasskeyCredential> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(credential => credential.Id);
        builder.Property(credential => credential.Id).ValueGeneratedNever();

        builder.Property(credential => credential.CredentialId).HasMaxLength(CredentialIdLength).IsRequired();

        builder.Property(credential => credential.PublicKey).HasMaxLength(1024).IsRequired();

        builder.Property(credential => credential.Transports).HasMaxLength(128);
        builder.Property(credential => credential.AttestationFormat).HasMaxLength(64);
        builder.Property(credential => credential.Label).HasMaxLength(128);

        builder.Property(credential => credential.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.LastUsedAt).HasConversion(InstantConverters.NullableInstant);

        // Unique across every account, not per user: a passwordless assertion carries only the
        // credential id, so it must identify the owner on its own.
        builder.HasIndex(credential => credential.CredentialId).IsUnique();
        builder.HasIndex(credential => credential.UserId);

        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(credential => credential.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ToamaisutaaPasskeyChallengeConfiguration : IEntityTypeConfiguration<ToamaisutaaPasskeyChallenge>
{
    public const string TableName = "ToamaisutaaPasskeyChallenges";

    public void Configure(EntityTypeBuilder<ToamaisutaaPasskeyChallenge> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(challenge => challenge.Id);
        builder.Property(challenge => challenge.Id).ValueGeneratedNever();

        builder.Property(challenge => challenge.TokenHash).HasMaxLength(64).IsRequired();

        // Deliberately unbounded: the options carry the allowed credential list, which grows with the
        // account's passkeys.
        builder.Property(challenge => challenge.Options).IsRequired();

        builder.Property(challenge => challenge.Ceremony).IsRequired();

        builder.Property(challenge => challenge.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(challenge => challenge.TokenHash).IsUnique();

        // Optional, because an assertion begun without an identifier belongs to nobody yet.
        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(challenge => challenge.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
