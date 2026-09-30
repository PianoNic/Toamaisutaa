namespace Toamaisutaa.Abstractions;

/// <summary>
/// Listing and revoking the devices a user has trusted.
/// </summary>
public interface ITrustedDeviceService
{
    Task<IReadOnlyList<TrustedDeviceSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>False when the device does not exist or belongs to someone else - deliberately the
    /// same answer, so another account's device ids cannot be discovered.</summary>
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

    /// <summary>True for the device making the request.</summary>
    public required bool IsCurrent { get; init; }
}
