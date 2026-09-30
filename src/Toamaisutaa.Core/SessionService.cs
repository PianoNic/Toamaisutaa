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

        // Scoped to this user's own list, so another user's family id is indistinguishable from one
        // that never existed.
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

        // One family at a time because RevokeAllForUserAsync cannot spare the caller's own session.
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
    /// Filters out families a refresh would already refuse, since expired rows stay unrevoked in
    /// the table until presented.
    /// </summary>
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
