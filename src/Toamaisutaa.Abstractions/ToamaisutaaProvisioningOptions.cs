namespace Toamaisutaa.Abstractions;

/// <summary>Settings for the optional local user row. Provisioning is opt-in, so nothing here
/// applies unless the consumer registers it.</summary>
public sealed class ToamaisutaaProvisioningOptions
{
    /// <summary>Identifies the provider on the external login row. Defaults to the bearer scheme
    /// name; change it only when more than one issuer feeds the same table.</summary>
    public string ProviderKey { get; set; } = ToamaisutaaDefaults.ProviderKey;

    public ProfileSyncMode ProfileSyncMode { get; set; } = ProfileSyncMode.OnChange;

    /// <summary>How stale <see cref="ToamaisutaaExternalLogin.LastSignInAt"/> is allowed to get
    /// before it is written again. Stamping it on every request would reintroduce the per-request
    /// write that <see cref="ProfileSyncMode"/> exists to avoid. Ignored when the sync mode is
    /// <see cref="ProfileSyncMode.Never"/> (never stamped) or
    /// <see cref="ProfileSyncMode.EveryRequest"/> (always stamped).</summary>
    public TimeSpan SignInStampInterval { get; set; } = TimeSpan.FromHours(1);

    public ToamaisutaaClaimNames ClaimNames { get; set; } = new();
}

/// <summary>When the local row is refreshed from the token's claims.</summary>
public enum ProfileSyncMode
{
    /// <summary>Write the profile once, at creation, and never again.</summary>
    Never,

    /// <summary>Same as <see cref="Never"/> for an existing row. Kept distinct so the intent
    /// reads correctly at the call site and so a future "re-sync on demand" can tell them
    /// apart.</summary>
    FirstSignInOnly,

    /// <summary>Write only when a mapped claim actually differs from the stored value.</summary>
    OnChange,

    /// <summary>Write on every request. Costs one round trip per request and exists only for
    /// consumers who want the row to track the token unconditionally.</summary>
    EveryRequest,
}

/// <summary>Which claim types the default mapper reads. Provider-agnostic, so it is configuration
/// rather than code.</summary>
public sealed class ToamaisutaaClaimNames
{
    public string Subject { get; set; } = "sub";

    public string Issuer { get; set; } = "iss";

    public string UserName { get; set; } = "preferred_username";

    public string Email { get; set; } = "email";

    public string DisplayName { get; set; } = "name";

    public string Picture { get; set; } = "picture";
}
