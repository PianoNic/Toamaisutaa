using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The challenge half of holding a sign-in back for an unverified address. Stores and the method are
/// resolved through the provider, so password login with the option off needs neither.
/// </summary>
internal sealed class EmailVerificationGate(
    IServiceProvider provider,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    ILogger<EmailVerificationGate> logger)
{
    internal bool Required => options.Value.RequireVerifiedEmailForSignIn;

    internal IEmailVerificationMethod Method => provider.GetRequiredService<IEmailVerificationMethod>();

    /// <summary>A refused delivery still hands back the challenge, so the person can ask again once it works.</summary>
    internal async Task<EmailVerificationChallenge> IssueChallengeAsync(
        ToamaisutaaUser user,
        ToamaisutaaPasswordCredential credential,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var email = credential.Email ?? throw new InvalidOperationException($"Credential for user {user.Id} has no address to verify.");
        var lifetime = options.Value.EmailVerificationChallengeLifetime;
        var raw = SecureTokens.Create();

        await provider.GetRequiredService<IEmailVerificationChallengeStore>().CreateAsync(
            new ToamaisutaaEmailVerificationChallenge
            {
                Id = Guid.CreateVersion7(now),
                UserId = user.Id,
                TokenHash = SecureTokens.HashToken(raw),
                NormalizedEmail = Normalizer.Normalize(email),
                SecurityStamp = user.SecurityStamp,
                CreatedAt = now,
                ExpiresAt = now + lifetime,
            },
            cancellationToken);

        var method = Method;

        try
        {
            await SendAsync(method, user, email, now, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            logger.LogError(ex, "Email verification for user {UserId} could not be sent. The challenge was issued; the person can ask again.", user.Id);
        }

        return new EmailVerificationChallenge(raw, (int)lifetime.TotalSeconds) { Method = method.Name, Email = Mask(email) };
    }

    internal async Task<EmailVerificationIssueResult> SendAsync(
        IEmailVerificationMethod method,
        ToamaisutaaUser user,
        string email,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var issued = await method.IssueAsync(new EmailVerificationIssueRequest { User = user, Email = email }, cancellationToken);

        if (issued.Outcome == EmailVerificationIssueOutcome.Sent)
            await events.PublishAsync(new EmailVerificationSent { OccurredAt = now, UserId = user.Id, Method = method.Name }, cancellationToken);
        else
            logger.LogInformation("Email verification for user {UserId} not sent again: one went out moments ago.", user.Id);

        return issued;
    }

    internal async Task<ToamaisutaaEmailVerificationChallenge?> FindAsync(string challengeToken, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(challengeToken)
            ? null
            : await provider.GetRequiredService<IEmailVerificationChallengeStore>().FindByHashAsync(SecureTokens.HashToken(challengeToken), cancellationToken);

    internal Task<bool> ConsumeAsync(Guid challengeId, DateTimeOffset now, CancellationToken cancellationToken) =>
        provider.GetRequiredService<IEmailVerificationChallengeStore>().MarkConsumedAsync(challengeId, now, cancellationToken);

    /// <summary>
    /// Enough for "we sent it to a***@example.com", and no more: whoever holds the challenge typed the
    /// password, but the response may be logged.
    /// </summary>
    internal static string Mask(string email)
    {
        var at = email.LastIndexOf('@');

        return at <= 0 ? "***" : $"{email[0]}***{email[at..]}";
    }
}
