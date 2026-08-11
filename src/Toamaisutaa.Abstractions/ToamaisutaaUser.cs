namespace Toamaisutaa.Abstractions;

/// <summary>
/// The local user row. A plain object with no attributes and no navigation properties, so
/// Abstractions stays dependency-free and the EF layer is free to configure it however a given
/// provider needs. Reach external logins through <see cref="IExternalLoginStore"/> rather than a
/// navigation property.
/// </summary>
public class ToamaisutaaUser
{
    public Guid Id { get; set; }

    public string? UserName { get; set; }

    public string? Email { get; set; }

    public string? DisplayName { get; set; }

    public string? PictureUrl { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
