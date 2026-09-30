using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The one place a local session is minted, for password and passkey sign-in alike; a second copy
/// would be a second answer to what a token carries, and those drift.
/// </summary>
internal sealed class LocalSessionIssuer(
    IAccessTokenIssuer accessTokens,
    IRefreshTokenStore refreshTokens,
    IUserRoleProvider roles,
    TwoFactorGate twoFactor,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    IServiceProvider provider)
{
    internal async Task<IssuedSession> IssueAsync(LocalSessionRequest request, CancellationToken cancellationToken)
    {
        var user = request.User;
        var userRoles = await roles.GetRolesAsync(user, cancellationToken);

        // The token and the row must carry the same family: toa_sid is how step-up finds the row.
        var family = request.FamilyId ?? Guid.CreateVersion7(request.Now);

        var access = await accessTokens.IssueAsync(
            new AccessTokenRequest
            {
                User = user,
                Roles = userRoles,

                // Recomputed on every issue, refresh included, so a verification or address change
                // shows up in the next token.
                VerifiedEmail = await VerifiedEmailAsync(user.Id, cancellationToken),

                AuthenticationMethods = request.Methods,

                // A passkey satisfies RequiredForAll without a TOTP enrolment, so the gate alone would
                // tell a user who already presented a second factor to enrol in another.
                TwoFactorEnrolmentRequired = request.TwoFactorSource is null
                    && await twoFactor.MustEnrolAsync(user.Id, cancellationToken),

                TwoFactorSource = request.TwoFactorSource,
                SecondFactorAt = request.SecondFactorAt,
                SessionId = family,
            },
            cancellationToken);

        var raw = SecureTokens.Create();

        await refreshTokens.CreateAsync(
            new ToamaisutaaRefreshToken
            {
                Id = Guid.CreateVersion7(request.Now),
                UserId = user.Id,
                FamilyId = family,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = request.Now,
                ExpiresAt = request.Now + options.Value.RefreshTokenLifetime,
                FamilyStartedAt = request.FamilyStartedAt ?? request.Now,
                SecurityStamp = user.SecurityStamp,

                // Carried on the family so a rotation does not downgrade a second-factor session.
                AuthenticationMethods = string.Join(' ', request.Methods),
                TwoFactorSource = request.TwoFactorSource,
                SecondFactorAt = request.SecondFactorAt,

                UserAgent = request.Client.UserAgent,
                IpAddress = request.Client.IpAddress,

                LastUsedAt = request.Now,
            },
            cancellationToken);

        // A refresh is not a sign-in; counting rotations would report one every AccessTokenLifetime.
        if (request.NewSignIn)
        {
            await events.PublishAsync(
                new SignInSucceeded
                {
                    OccurredAt = request.Now,
                    UserId = user.Id,
                    AuthenticationMethods = request.Methods,
                    SessionId = family,
                    TwoFactorSource = request.TwoFactorSource,
                },
                cancellationToken);
        }

        return new IssuedSession
        {
            FamilyId = family,
            Tokens = new TokenPair
            {
                AccessToken = access.Value,
                RefreshToken = raw,
                ExpiresIn = (int)Math.Max(0, (access.ExpiresAt - request.Now).TotalSeconds),
            },
        };
    }

    /// <summary>Resolved rather than injected: a passkey-only deployment registers no password store.</summary>
    internal async Task<string?> VerifiedEmailAsync(Guid userId, CancellationToken cancellationToken) =>
        provider.GetService(typeof(IPasswordCredentialStore)) is IPasswordCredentialStore store
            && await store.FindByUserIdAsync(userId, cancellationToken) is { EmailConfirmedAt: not null } credential
            ? credential.Email
            : null;
}

internal sealed record LocalSessionRequest
{
    internal required ToamaisutaaUser User { get; init; }

    internal Guid? FamilyId { get; init; }

    /// <summary>Carried on a refresh, so rotation cannot restart the family's absolute lifetime.</summary>
    internal DateTimeOffset? FamilyStartedAt { get; init; }

    internal required IReadOnlyList<string> Methods { get; init; }

    internal string? TwoFactorSource { get; init; }

    internal DateTimeOffset? SecondFactorAt { get; init; }

    internal required bool NewSignIn { get; init; }

    internal required ClientMetadata.SessionClient Client { get; init; }

    internal required DateTimeOffset Now { get; init; }
}

internal readonly record struct IssuedSession
{
    internal required Guid FamilyId { get; init; }

    internal required TokenPair Tokens { get; init; }
}
