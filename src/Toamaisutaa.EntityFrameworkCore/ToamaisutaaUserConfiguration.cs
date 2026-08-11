using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>Public so consumers who keep the tables in their own context can apply it
/// themselves, and call <c>ToTable</c> after it if they want different names.</summary>
public sealed class ToamaisutaaUserConfiguration : IEntityTypeConfiguration<ToamaisutaaUser>
{
    public const string TableName = "ToamaisutaaUsers";

    public void Configure(EntityTypeBuilder<ToamaisutaaUser> builder)
    {
        builder.ToTable(TableName);

        builder.HasKey(user => user.Id);

        // The store assigns a UUIDv7, so the two providers behave identically and a user and its
        // external login can be inserted in one round trip.
        builder.Property(user => user.Id).ValueGeneratedNever();

        builder.Property(user => user.UserName).HasMaxLength(256);
        builder.Property(user => user.Email).HasMaxLength(256);
        builder.Property(user => user.DisplayName).HasMaxLength(256);
        builder.Property(user => user.PictureUrl).HasMaxLength(2048);

        builder.Property(user => user.CreatedAt).HasConversion(InstantConverters.Instant);
        builder.Property(user => user.UpdatedAt).HasConversion(InstantConverters.Instant);

        // NOT UNIQUE, permanently, and not an oversight to be tidied up later.
        //
        // This model is multi-provider: one person with accounts at two identity providers is two
        // rows, legitimately sharing an address, and plenty of providers do not enforce uniqueness
        // in the first place. Email here is a profile field that OIDC provisioning rewrites whenever
        // the token's claim changes - making it unique would mean an administrator editing a
        // directory could collide two rows and throw out of an unrelated request.
        //
        // Local login does need a unique email, and it has one: ToamaisutaaPasswordCredentials owns
        // that constraint, scoped to accounts that actually sign in with a password.
        builder.HasIndex(user => user.Email);
    }
}
