namespace Toamaisutaa.Abstractions;

/// <summary>
/// Mints the short-lived access token a successful local sign-in returns.
/// </summary>
public interface IAccessTokenIssuer
{
    /// <summary>
    /// The resulting token must be indistinguishable downstream from one the identity provider
    /// issued: same claim shape, validated by the same pipeline, understood by the same policies.
    /// </summary>
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
    /// Not <see cref="ToamaisutaaUser.Email"/>, which holds whatever was typed at registration and
    /// would let anybody pass a policy keyed on someone else's address.
    /// </remarks>
    public string? VerifiedEmail { get; init; }

    /// <summary>
    /// RFC 8176 authentication method references, written to <c>amr</c>: <c>pwd</c> for a password,
    /// <c>otp</c> for a TOTP code, <c>mfa</c> whenever a second factor was actually presented.
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
