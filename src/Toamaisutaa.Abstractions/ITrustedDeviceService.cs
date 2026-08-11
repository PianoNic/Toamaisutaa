namespace Toamaisutaa.Abstractions;

/// <summary>
/// Listing and revoking the devices a user has trusted. A trust nobody can see or take back is a
/// liability, so this is not optional alongside the feature.
/// </summary>
public interface ITrustedDeviceService
{
    Task<IReadOnlyList<TrustedDeviceSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>False when the device does not exist or belongs to someone else - which are the same
    /// answer, so that this cannot be used to discover another account's device ids.</summary>
    Task<bool> RevokeAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken = default);

    /// <summary>Returns how many families were revoked.</summary>
    Task<int> RevokeAllAsync(Guid userId, CancellationToken cancellationToken = default);
}

public sealed record TrustedDeviceSummary
{
    /// <summary>The family id, which survives rotation. Pass it back to revoke.</summary>
    public required Guid Id { get; init; }

    public string? Label { get; init; }

    public string? UserAgent { get; init; }

    public string? IpAddress { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset LastUsedAt { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>True for the device making the request, so a list can say "this device" rather than
    /// inviting somebody to revoke the one they are sitting at.</summary>
    public required bool IsCurrent { get; init; }
}
