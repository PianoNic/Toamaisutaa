using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The one place a local session is minted: an access token, the refresh row behind it, and the
/// event that says a sign-in happened.
/// </summary>
/// <remarks>
/// Its own class because password login is no longer the only thing that ends in a token pair - a
/// passkey assertion does too, from a package that cannot live in <c>Core</c> because it carries a
/// WebAuthn dependency. A second copy of this would be a second answer to "what does a token carry
/// now", and that question has already been the bug three phases running.
/// </remarks>
internal sealed class LocalSessionIssuer(
    IAccessTokenIssuer accessTokens,
    IRefreshTokenStore refreshTokens,
    IUserRoleProvider roles,
    TwoFactorGate twoFactor,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options)
{
    internal async Task<IssuedSession> IssueAsync(LocalSessionRequest request, CancellationToken cancellationToken)
    {
        var user = request.User;
        var userRoles = await roles.GetRolesAsync(user, cancellationToken);

        // Computed before the token rather than inside the row, because both have to carry the same
        // value: toa_sid is how step-up finds the row this token belongs to, and a token naming a
        // family that does not exist can elevate nothing.
        var family = request.FamilyId ?? Guid.CreateVersion7(request.Now);

        var access = await accessTokens.IssueAsync(
            new AccessTokenRequest
            {
                User = user,
                Roles = userRoles,
                AuthenticationMethods = request.Methods,

                // A sign-in that already presented a second factor is not one to be told to enrol
                // in another. For a TOTP or device sign-in this changes nothing - the gate answers
                // no for an enrolled user anyway - but a passkey satisfies RequiredForAll without
                // any TOTP enrolment existing, and asking the gate alone would tell the one user
                // who did the most work to go and do more.
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

                // Carried on the family so a rotation does not quietly downgrade a session that was
                // established with a second factor into one that only ever proved a password.
                AuthenticationMethods = string.Join(' ', request.Methods),
                TwoFactorSource = request.TwoFactorSource,
                SecondFactorAt = request.SecondFactorAt,

                UserAgent = request.Client.UserAgent,
                IpAddress = request.Client.IpAddress,

                // The live row of a family is always the newest one, so this is the family's own
                // last activity without anything ever writing over a row in place.
                LastUsedAt = request.Now,
            },
            cancellationToken);

        // A refresh lands here too, and it is not a sign-in: it proved nothing, it renewed
        // something already proved. An audit table that counted rotations as sign-ins would report
        // one every AccessTokenLifetime for anyone who left a tab open.
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
}

/// <summary>
/// Everything a session needs to be minted from.
/// </summary>
/// <remarks>
/// A record rather than an argument list, for the reason <see cref="AccessTokenRequest"/> is one:
/// what a token has to carry has grown every phase so far, and each growth widened a signature.
/// </remarks>
internal sealed record LocalSessionRequest
{
    internal required ToamaisutaaUser User { get; init; }

    /// <summary>Null for a new sign-in. Set on a refresh, which stays in the family it rotated out
    /// of.</summary>
    internal Guid? FamilyId { get; init; }

    /// <summary>Null for a new sign-in. Carried on a refresh, so rotation cannot restart the clock
    /// on the family's absolute lifetime.</summary>
    internal DateTimeOffset? FamilyStartedAt { get; init; }

    /// <summary>The RFC 8176 methods this session proved.</summary>
    internal required IReadOnlyList<string> Methods { get; init; }

    /// <summary>One of <see cref="TwoFactorSource"/>, or null when no second factor was involved.</summary>
    internal string? TwoFactorSource { get; init; }

    internal DateTimeOffset? SecondFactorAt { get; init; }

    /// <summary>False for a refresh, which renewed something rather than proving it.</summary>
    internal required bool NewSignIn { get; init; }

    internal required ClientMetadata.SessionClient Client { get; init; }

    internal required DateTimeOffset Now { get; init; }
}

internal readonly record struct IssuedSession
{
    /// <summary>The refresh family, which is what <c>toa_sid</c> carries.</summary>
    internal required Guid FamilyId { get; init; }

    internal required TokenPair Tokens { get; init; }
}
