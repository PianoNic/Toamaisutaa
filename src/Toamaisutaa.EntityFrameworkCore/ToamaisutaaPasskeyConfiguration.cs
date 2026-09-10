using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

public sealed class ToamaisutaaPasskeyCredentialConfiguration : IEntityTypeConfiguration<ToamaisutaaPasskeyCredential>
{
    public const string TableName = "ToamaisutaaPasskeyCredentials";

    /// <summary>
    /// What the credential id column holds at most. WebAuthn allows up to 1023 bytes, but the
    /// column is unique and MySQL's InnoDB caps an index key at 3072, so the whole span cannot be
    /// indexed on every provider. 256 covers every authenticator in circulation - the specification
    /// itself recommends 64 - and a longer one is refused at registration with a message that says
    /// so rather than by a truncating insert.
    /// </summary>
    public const int CredentialIdLength = 256;

    public void Configure(EntityTypeBuilder<ToamaisutaaPasskeyCredential> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(credential => credential.Id);
        builder.Property(credential => credential.Id).ValueGeneratedNever();

        builder.Property(credential => credential.CredentialId).HasMaxLength(CredentialIdLength).IsRequired();

        // A COSE key, not a certificate. An RSA-2048 one is about 300 bytes and an EC one under
        // 100; sized well past both because the column is not indexed and nothing is saved by
        // sizing it tightly.
        builder.Property(credential => credential.PublicKey).HasMaxLength(1024).IsRequired();

        builder.Property(credential => credential.Transports).HasMaxLength(128);
        builder.Property(credential => credential.AttestationFormat).HasMaxLength(64);
        builder.Property(credential => credential.Label).HasMaxLength(128);

        builder.Property(credential => credential.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(credential => credential.LastUsedAt).HasConversion(InstantConverters.NullableInstant);

        // Unique across every account, not per user: a passwordless assertion arrives carrying a
        // credential id and nothing else, so two rows sharing one would make "whose credential is
        // this" unanswerable rather than merely awkward.
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

        // The WebAuthn options as JSON. Deliberately unbounded: it carries the allowed credential
        // list, which grows with how many passkeys the account has, and a length that fits ten
        // would silently corrupt the eleventh.
        builder.Property(challenge => challenge.Options).IsRequired();

        // Stored as the integer the enum already is, matching the two-factor challenge next to it.
        builder.Property(challenge => challenge.Ceremony).IsRequired();

        builder.Property(challenge => challenge.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ExpiresAt).HasConversion(InstantConverters.Instant);
        builder.Property(challenge => challenge.ConsumedAt).HasConversion(InstantConverters.NullableInstant);

        builder.HasIndex(challenge => challenge.TokenHash).IsUnique();

        // Optional, because an assertion begun without an identifier belongs to nobody yet - the
        // browser picks the credential and the server learns who it is at the end.
        builder.HasOne<ToamaisutaaUser>()
            .WithMany()
            .HasForeignKey(challenge => challenge.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
