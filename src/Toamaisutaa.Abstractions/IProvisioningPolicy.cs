namespace Toamaisutaa.Abstractions;

/// <summary>
/// Decides what provisioning should do with a mapped profile. Pure: it touches no storage.
/// </summary>
public interface IProvisioningPolicy
{
    ProvisioningDecision Decide(ProvisioningContext context);
}

/// <summary>Everything the policy is allowed to look at.</summary>
public sealed record ProvisioningContext
{
    public required string ProviderKey { get; init; }

    public required ExternalUserProfile Profile { get; init; }

    public required ProfileSyncMode SyncMode { get; init; }

    /// <summary>The existing link for this (provider, subject), if there is one.</summary>
    public ToamaisutaaExternalLogin? ExistingLogin { get; init; }

    /// <summary>The user behind <see cref="ExistingLogin"/>.</summary>
    public ToamaisutaaUser? LinkedUser { get; init; }

    /// <summary>An existing local user this subject should attach to instead of getting a new row.
    /// Currently always null, since linking is by subject only.</summary>
    public ToamaisutaaUser? LinkCandidate { get; init; }
}

public enum ProvisioningAction
{
    /// <summary>This subject is already linked. Nothing to create.</summary>
    AlreadyLinked,

    /// <summary>Attach this subject to an existing user.</summary>
    LinkExisting,

    /// <summary>Create a user and link this subject to it.</summary>
    CreateNew,
}

public sealed record ProvisioningDecision
{
    public required ProvisioningAction Action { get; init; }

    /// <summary>The user the action targets. Null for <see cref="ProvisioningAction.CreateNew"/>.</summary>
    public Guid? UserId { get; init; }

    public Guid? ExternalLoginId { get; init; }

    /// <summary>Whether the stored profile should be rewritten from the token. Never set for
    /// <see cref="ProvisioningAction.CreateNew"/>, where the insert already writes it.</summary>
    public bool ProfileNeedsUpdate { get; init; }
}
