namespace Toamaisutaa.Abstractions;

/// <summary>
/// Mints the short-lived access token a successful local sign-in returns. Implemented outside
/// <c>Core</c>, because signing a JWT needs a JWT library and Core carries no third-party packages.
/// </summary>
public interface IAccessTokenIssuer
{
    /// <summary>
    /// The resulting token must be indistinguishable downstream from one the identity provider
    /// issued: same claim shape, validated by the same pipeline, understood by the same policies.
    /// </summary>
    /// <remarks>
    /// Asynchronous even though the shipped implementation signs in memory and never waits for
    /// anything. Signing is exactly the operation that later moves to a key management service or an
    /// HSM, and by then this is a published interface that cannot change shape.
    /// <para>
    /// The parameter is a record rather than an argument list for the same reason: everything a
    /// token needs to carry has arrived here so far by widening the signature, which breaks every
    /// implementer. Adding a property does not.
    /// </para>
    /// </remarks>
    Task<AccessToken> IssueAsync(AccessTokenRequest request, CancellationToken cancellationToken = default);
}

public sealed record AccessTokenRequest
{
    public required ToamaisutaaUser User { get; init; }

    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>
    /// The address the token may assert in <c>email</c>: the local credential's, and only once it
    /// has been verified. Null otherwise, and then the token carries no <c>email</c> at all.
    /// </summary>
    /// <remarks>
    /// Not <see cref="ToamaisutaaUser.Email"/>. Registration writes whatever address it is typed,
    /// and a token asserting it under the same claim an identity provider uses let anybody register
    /// as someone else's address and pass every policy keyed on it.
    /// </remarks>
    public string? VerifiedEmail { get; init; }

    /// <summary>
    /// RFC 8176 authentication method references, written to <c>amr</c>: <c>pwd</c> for a password,
    /// <c>otp</c> for a TOTP code, <c>mfa</c> whenever a second factor was actually presented.
    /// Standard rather than invented, so anything that already reads <c>amr</c> keeps working.
    /// </summary>
    public IReadOnlyList<string> AuthenticationMethods { get; init; } = [];

    /// <summary>
    /// True under <see cref="TwoFactorEnforcement.RequiredForAll"/> when this user has not enrolled
    /// yet, written to <c>toa_2fa_required</c>. It is what lets an application keep the enrolment
    /// endpoints reachable while everything else demands the policy.
    /// </summary>
    public bool TwoFactorEnrolmentRequired { get; init; }

    /// <summary>
    /// How the second factor was satisfied, written to <c>toa_2fa_source</c>. One of
    /// <see cref="TwoFactorSource"/>, or null when no second factor was involved.
    /// </summary>
    public string? TwoFactorSource { get; init; }

    /// <summary>
    /// When a second factor was last actually presented, written to <c>toa_2fa_at</c> as Unix
    /// seconds. For a device-trusted sign-in this is the original live challenge, not now, which is
    /// what lets an application require a <i>fresh</i> factor rather than merely a cached one.
    /// </summary>
    public DateTimeOffset? SecondFactorAt { get; init; }

    /// <summary>
    /// The refresh family this token belongs to, written to <c>toa_sid</c>. Null for a token that
    /// belongs to no local session, which is how a caller is told step-up has nothing to elevate.
    /// </summary>
    public Guid? SessionId { get; init; }
}

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);
