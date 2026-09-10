using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class SessionService(
    IRefreshTokenStore refreshTokens,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<SessionService> logger) : ISessionService
{
    public async Task<IReadOnlyList<SessionSummary>> ListAsync(
        Guid userId,
        Guid? currentSessionId = null,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        return
        [
            .. (await LiveAsync(userId, now, cancellationToken))
                .OrderByDescending(session => session.Token.LastUsedAt)
                .Select(session => new SessionSummary
                {
                    Id = session.Token.FamilyId,
                    UserAgent = session.Token.UserAgent,
                    IpAddress = session.Token.IpAddress,
                    CreatedAt = session.Token.FamilyStartedAt,
                    LastUsedAt = session.Token.LastUsedAt,
                    ExpiresAt = session.EndsAt,
                    AuthenticationMethods = session.Token.AuthenticationMethods.Length == 0
                        ? []
                        : session.Token.AuthenticationMethods.Split(' '),
                    IsCurrent = currentSessionId == session.Token.FamilyId,
                }),
        ];
    }

    public async Task<bool> RevokeAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        // Scoped to this user's own list, so a family id belonging to someone else is
        // indistinguishable from one that never existed.
        if (!(await LiveAsync(userId, now, cancellationToken)).Any(session => session.Token.FamilyId == sessionId))
            return false;

        await RevokeAsync(userId, sessionId, now, cancellationToken);
        logger.LogInformation("User {UserId} revoked session {FamilyId}.", userId, sessionId);

        return true;
    }

    public async Task<int> RevokeAllExceptAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        var revoked = 0;

        // One family at a time rather than one statement over the user, because the caller's own
        // session has to survive and RevokeAllForUserAsync has no way to spare it.
        foreach (var session in await LiveAsync(userId, now, cancellationToken))
        {
            if (session.Token.FamilyId == currentSessionId)
                continue;

            await RevokeAsync(userId, session.Token.FamilyId, now, cancellationToken);
            revoked++;
        }

        logger.LogInformation("User {UserId} signed out everywhere else: {Count} session(s) revoked.", userId, revoked);

        return revoked;
    }

    /// <summary>
    /// Revokes one family and publishes it, so an audit sink hears about a session the user ended
    /// themselves as well as the ones a credential change ended for them.
    /// </summary>
    private async Task RevokeAsync(Guid userId, Guid sessionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await refreshTokens.RevokeFamilyAsync(sessionId, "revoked-by-user", now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked
            {
                OccurredAt = now,
                UserId = userId,
                SessionId = sessionId,
                Reason = "revoked-by-user",
            },
            cancellationToken);
    }

    /// <summary>
    /// The live row of each family, minus the ones a refresh would already refuse.
    /// </summary>
    /// <remarks>
    /// A family whose token has expired, or which has reached its absolute lifetime, is still
    /// unrotated and unrevoked in the table until somebody presents it - the refusal happens on the
    /// refresh path, not on a timer. Listing those would offer the user sessions that are already
    /// over, and revoking one would be a 204 that changed nothing anybody could observe.
    /// </remarks>
    private async Task<IReadOnlyList<(ToamaisutaaRefreshToken Token, DateTimeOffset EndsAt)>> LiveAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var absolute = options.Value.RefreshTokenAbsoluteLifetime;

        return
        [
            .. (await refreshTokens.ListActiveAsync(userId, cancellationToken))
                .Select(token => (Token: token, EndsAt: Earlier(token.ExpiresAt, token.FamilyStartedAt + absolute)))
                .Where(session => session.EndsAt > now),
        ];
    }

    private static DateTimeOffset Earlier(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;
}
