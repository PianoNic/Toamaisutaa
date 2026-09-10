using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class PasswordAccountService(
    IPasswordCredentialStore credentials,
    IUserStore users,
    IRefreshTokenStore refreshTokens,
    IPasswordResetTokenStore resetTokens,
    IInvitationTokenStore invitationTokens,
    IEmailVerificationTokenStore emailVerificationTokens,
    IMagicLinkTokenStore magicLinkTokens,
    IPasswordHasher hasher,
    IPasswordValidator validator,
    IPasswordResetNotifier notifier,
    IPasswordSignInService signIn,
    TrustedDeviceGate trustedDevices,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<PasswordAccountService> logger,
    IServiceProvider serviceProvider) : IPasswordAccountService
{
    public async Task<AccountResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.UserName))
            return AccountResult.Failure("Choose a user name.");

        var errors = await validator.ValidateAsync(request.Password, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var now = timeProvider.GetUtcNow();

        var user = await users.CreateAsync(
            new ToamaisutaaUser
            {
                UserName = request.UserName.Trim(),
                Email = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email.Trim(),
                DisplayName = request.UserName.Trim(),
                SecurityStamp = SecureTokens.Create(),
            },
            cancellationToken);

        try
        {
            await credentials.CreateAsync(
                BuildCredential(user.Id, request.UserName.Trim(), request.Email, request.Password, now),
                cancellationToken);
        }
        catch (PasswordIdentifierConflictException)
        {
            // The user row is already written and now owns nothing. Leaving it would accumulate
            // empty accounts on every collision, so take it back out.
            await users.DeleteAsync(user.Id, cancellationToken);
            logger.LogInformation("Registration refused: the user name or email is already in use.");
            return AccountResult.Taken("That user name or email address is already in use.");
        }

        logger.LogInformation("Registered local account for user {UserId}.", user.Id);

        var tokens = await signIn.SignInAsync(
            new PasswordSignInRequest { Identifier = request.UserName.Trim(), Password = request.Password },
            cancellationToken);

        return new AccountResult { Succeeded = true, UserId = user.Id, Tokens = tokens.Tokens };
    }

    public async Task<AccountResult> SetPasswordAsync(
        Guid userId,
        string? currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return AccountResult.Failure("That account no longer exists.");

        var errors = await validator.ValidateAsync(newPassword, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var now = timeProvider.GetUtcNow();
        var credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            // An account that arrived through an identity provider, adding a password for the first
            // time. There is no current password to prove, because there is none.
            if (currentPassword is not null)
                return AccountResult.Failure("This account has no password yet, so there is no current password to give.");

            var userName = user.UserName ?? user.Email;
            if (string.IsNullOrWhiteSpace(userName))
                return AccountResult.Failure("This account has no user name or email address to sign in with. Set one first.");

            try
            {
                await credentials.CreateAsync(
                    BuildCredential(userId, userName.Trim(), user.Email, newPassword, now),
                    cancellationToken);
            }
            catch (PasswordIdentifierConflictException)
            {
                return AccountResult.Failure("Another local account already uses that user name or email address.");
            }

            logger.LogInformation("Added a local password to user {UserId}, which had none.", userId);
        }
        else
        {
            if (currentPassword is null)
                return AccountResult.Failure("Give your current password.");

            if (hasher.Verify(currentPassword, credential.PasswordHash) == PasswordVerificationResult.Failed)
            {
                logger.LogWarning("Password change refused for user {UserId}: the current password is wrong.", userId);
                return AccountResult.Failure("Your current password is not correct.");
            }

            ApplyNewPassword(credential, newPassword, now);
            await credentials.UpdateAsync(credential, cancellationToken);
            logger.LogInformation("Changed the password for user {UserId}.", userId);
        }

        // A password change ends the other sessions. It is the one moment the account holder is
        // most likely to be reacting to someone else having access.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(userId, "password-changed", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "password-changed", now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

        await events.PublishAsync(new PasswordChanged { OccurredAt = now, UserId = userId }, cancellationToken);

        // An outstanding change of address is a credential in flight too: whoever was in this
        // account a moment ago may have pointed it at a mailbox of their own, and the link is still
        // sitting there.
        await emailVerificationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

        return new AccountResult { Succeeded = true, UserId = userId };
    }

    public async Task<AccountResult> AdminCreateAccountAsync(
        string userName,
        string? email,
        string? password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName))
            return AccountResult.Failure("Choose a user name.");

        var adminNotifier = ResolveAdminPasswordNotifier();
        var effectivePassword = password ?? AdminPasswordGenerator.Generate();

        var errors = await validator.ValidateAsync(effectivePassword, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var now = timeProvider.GetUtcNow();

        var user = await users.CreateAsync(
            new ToamaisutaaUser
            {
                UserName = userName.Trim(),
                Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
                DisplayName = userName.Trim(),
                SecurityStamp = SecureTokens.Create(),
            },
            cancellationToken);

        try
        {
            await credentials.CreateAsync(BuildCredential(user.Id, userName.Trim(), email, effectivePassword, now), cancellationToken);
        }
        catch (PasswordIdentifierConflictException)
        {
            // Same rule as self-registration: an account that ends up owning nothing accumulates
            // forever if it is left behind.
            await users.DeleteAsync(user.Id, cancellationToken);
            logger.LogInformation("Admin account creation refused: the user name or email is already in use.");
            return AccountResult.Taken("That user name or email address is already in use.");
        }

        // The only moment this password exists in the clear outside the hasher. Handed to the
        // caller's own notifier, never returned from this call and never logged.
        await adminNotifier.PasswordIssuedAsync(user, effectivePassword, cancellationToken);

        logger.LogInformation("Admin-created local account for user {UserId}.", user.Id);

        return new AccountResult { Succeeded = true, UserId = user.Id };
    }

    public async Task<AccountResult> AdminSetPasswordAsync(Guid userId, string? password, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return AccountResult.Failure("That account no longer exists.");

        var adminNotifier = ResolveAdminPasswordNotifier();
        var effectivePassword = password ?? AdminPasswordGenerator.Generate();

        var errors = await validator.ValidateAsync(effectivePassword, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var now = timeProvider.GetUtcNow();
        var credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            var identifier = user.UserName ?? user.Email;
            if (string.IsNullOrWhiteSpace(identifier))
                return AccountResult.Failure("This account has no user name or email address to sign in with. Set one first.");

            try
            {
                await credentials.CreateAsync(BuildCredential(userId, identifier.Trim(), user.Email, effectivePassword, now), cancellationToken);
            }
            catch (PasswordIdentifierConflictException)
            {
                return AccountResult.Failure("Another local account already uses that user name or email address.");
            }
        }
        else
        {
            // Unconditional, unlike the self-service path: there is no current password to prove,
            // because the caller here is acting on someone else's account, not their own.
            ApplyNewPassword(credential, effectivePassword, now);
            await credentials.UpdateAsync(credential, cancellationToken);
        }

        await adminNotifier.PasswordIssuedAsync(user, effectivePassword, cancellationToken);

        // Same reasoning as a self-service change: whoever is now holding this password should not
        // find the account's other sessions still alive.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(userId, "admin-password-set", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "admin-password-set", now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await emailVerificationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

        await events.PublishAsync(
            new PasswordChanged { OccurredAt = now, UserId = userId, SetByAdministrator = true },
            cancellationToken);

        logger.LogInformation("Admin set the password for user {UserId}; all local sessions revoked.", userId);

        return new AccountResult { Succeeded = true, UserId = userId };
    }

    public async Task<AccountResult> RequestEmailChangeAsync(
        Guid userId,
        string newEmail,
        string currentPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newEmail);
        ArgumentNullException.ThrowIfNull(currentPassword);

        if (string.IsNullOrWhiteSpace(newEmail))
            return AccountResult.Failure("Give an email address.");

        var user = await users.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return AccountResult.Failure("That account no longer exists.");

        var verificationNotifier = ResolveEmailVerificationNotifier();
        var credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            // No local credential means no local email to change: the address on the profile belongs
            // to the identity provider that wrote it, and changing it here would be overwritten on
            // the next sign-in.
            return AccountResult.Failure("This account has no local password, so its email address is not ours to change.");
        }

        if (hasher.Verify(currentPassword, credential.PasswordHash) == PasswordVerificationResult.Failed)
        {
            logger.LogWarning("Email change refused for user {UserId}: the current password is wrong.", userId);
            return AccountResult.Failure("Your current password is not correct.");
        }

        var trimmed = newEmail.Trim();
        var normalized = Normalizer.Normalize(trimmed);

        // Checked here as well as on redemption. Doing it only on redemption would mail a link that
        // cannot work, and the person holding it has no way to tell that from a broken link.
        var holder = await credentials.FindByNormalizedEmailAsync(normalized, cancellationToken);
        if (holder is not null && holder.UserId != userId)
        {
            logger.LogInformation("Email change refused for user {UserId}: another local account already uses that address.", userId);
            return AccountResult.Taken("That email address is already in use.");
        }

        var now = timeProvider.GetUtcNow();

        // Asking for a second address retires the link sent to the first, so only the most recent
        // request can ever be redeemed.
        await emailVerificationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

        var raw = SecureTokens.Create();

        await emailVerificationTokens.CreateAsync(
            new ToamaisutaaEmailVerificationToken
            {
                Id = Guid.CreateVersion7(now),
                UserId = userId,
                Email = trimmed,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.EmailVerificationTokenLifetime,
            },
            cancellationToken);

        await verificationNotifier.SendAsync(user, trimmed, raw, cancellationToken);

        logger.LogInformation("Email verification token issued for user {UserId} and handed to the notifier.", userId);

        return new AccountResult { Succeeded = true, UserId = userId };
    }

    public async Task<AccountResult> VerifyEmailAsync(string verificationToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verificationToken);

        var now = timeProvider.GetUtcNow();
        var stored = await emailVerificationTokens.FindByHashAsync(SecureTokens.HashToken(verificationToken), cancellationToken);

        // One message for every way this can fail, the same reasoning ResetPasswordAsync uses.
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now)
        {
            logger.LogWarning("Email verification refused: the token is unknown, already used or expired.");
            return AccountResult.Failure("That verification link is no longer valid. Request a new one.");
        }

        var credential = await credentials.FindByUserIdAsync(stored.UserId, cancellationToken);
        if (credential is null)
            return AccountResult.Failure("That verification link is no longer valid. Request a new one.");

        var normalized = Normalizer.Normalize(stored.Email);

        // Checked again, because the link may have sat in a mailbox for a day while somebody else
        // took the address. The unique index would answer this too, as an exception rather than a
        // sentence the person can read.
        var holder = await credentials.FindByNormalizedEmailAsync(normalized, cancellationToken);
        if (holder is not null && holder.UserId != stored.UserId)
        {
            logger.LogInformation("Email verification refused for user {UserId}: another local account now uses that address.", stored.UserId);
            return AccountResult.Taken("That email address is already in use.");
        }

        credential.Email = stored.Email;
        credential.NormalizedEmail = normalized;
        credential.EmailConfirmedAt = now;
        credential.UpdatedAt = now;

        await credentials.UpdateAsync(credential, cancellationToken);
        await emailVerificationTokens.MarkConsumedAsync(stored.Id, now, cancellationToken);
        await emailVerificationTokens.InvalidateAllForUserAsync(stored.UserId, now, cancellationToken);

        // The profile field follows the login identifier, so the reset and invitation notifiers stop
        // addressing mail to where this account used to be. Nothing else moves: sessions stay alive,
        // because proving an address is not a credential change.
        await users.SetEmailAsync(stored.UserId, stored.Email, cancellationToken);

        logger.LogInformation("Email verified for user {UserId}.", stored.UserId);

        return new AccountResult { Succeeded = true, UserId = stored.UserId };
    }

    public async Task<MagicLinkRequestOutcome> RequestMagicLinkAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        var magicLinkNotifier = ResolveMagicLinkNotifier();

        var normalized = Normalizer.NormalizeOptional(email);
        if (normalized is null)
            return MagicLinkRequestOutcome.UnknownEmail;

        var credential = await credentials.FindByNormalizedEmailAsync(normalized, cancellationToken);

        if (credential is null)
        {
            // Told apart in the log and nowhere else, the same three cases password reset separates
            // and for the same reason: a caller who can tell them apart can enumerate addresses.
            var known = await users.FindByEmailAsync(email.Trim(), cancellationToken);

            if (known is not null)
            {
                logger.LogInformation(
                    "Magic link requested for user {UserId}, which has no local credential - an identity provider owns it. "
                    + "No email sent; the person should sign in with their provider.",
                    known.Id);

                return MagicLinkRequestOutcome.NoLocalCredential;
            }

            logger.LogInformation("Magic link requested for an address with no account. Nothing sent.");
            return MagicLinkRequestOutcome.UnknownEmail;
        }

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken);
        if (user is null)
            return MagicLinkRequestOutcome.UnknownEmail;

        // Not an option, unlike the password-reset rule this mirrors. A reset link leads to a form
        // that asks for a new password; this one is exchanged for a session, so an address that is a
        // typo or that somebody else now owns is an account handed over.
        if (credential.EmailConfirmedAt is null)
        {
            logger.LogInformation(
                "Magic link requested for user {UserId}, whose email address has never been verified. No email sent; "
                + "the address has to be verified at /auth/email first.",
                credential.UserId);

            return MagicLinkRequestOutcome.EmailNotVerified;
        }

        var now = timeProvider.GetUtcNow();

        // Asking for a new link retires the old ones, so a mailbox never holds two that work.
        await magicLinkTokens.InvalidateAllForUserAsync(credential.UserId, now, cancellationToken);

        var raw = SecureTokens.Create();

        await magicLinkTokens.CreateAsync(
            new ToamaisutaaMagicLinkToken
            {
                Id = Guid.CreateVersion7(now),
                UserId = credential.UserId,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.MagicLinkTokenLifetime,
            },
            cancellationToken);

        try
        {
            await magicLinkNotifier.SendAsync(user, raw, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Same reasoning as the reset notifier: an unhandled exception here would answer 500 for
            // a real address and 204 for an unknown one, which is exactly the distinction "always
            // 204" was meant to erase.
            logger.LogError(ex, "Magic-link notifier failed for user {UserId}. The token was issued; no email was sent.", credential.UserId);
            return MagicLinkRequestOutcome.NotificationFailed;
        }

        logger.LogInformation("Magic-link token issued for user {UserId} and handed to the notifier.", credential.UserId);
        return MagicLinkRequestOutcome.Sent;
    }

    public async Task<AccountResult> CreateInvitationAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        if (string.IsNullOrWhiteSpace(email))
            return AccountResult.Failure("Give an email address.");

        var invitationNotifier = ResolveInvitationNotifier();
        var now = timeProvider.GetUtcNow();

        // No user name and no credential - the row exists to be completed, not signed into. It is
        // deliberately not a match for RegisterAsync's shape: nothing here is a finished account yet.
        var user = await users.CreateAsync(
            new ToamaisutaaUser
            {
                Email = email.Trim(),
                SecurityStamp = SecureTokens.Create(),
            },
            cancellationToken);

        var raw = SecureTokens.Create();

        await invitationTokens.CreateAsync(
            new ToamaisutaaInvitationToken
            {
                Id = Guid.CreateVersion7(now),
                UserId = user.Id,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.InvitationTokenLifetime,
            },
            cancellationToken);

        await invitationNotifier.SendAsync(user, raw, cancellationToken);

        logger.LogInformation("Invitation created for user {UserId} and handed to the notifier.", user.Id);

        return new AccountResult { Succeeded = true, UserId = user.Id };
    }

    public async Task<AccountResult> CompleteInvitationAsync(
        string invitationToken,
        string userName,
        string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitationToken);

        if (string.IsNullOrWhiteSpace(userName))
            return AccountResult.Failure("Choose a user name.");

        var now = timeProvider.GetUtcNow();
        var stored = await invitationTokens.FindByHashAsync(SecureTokens.HashToken(invitationToken), cancellationToken);

        // One message for every way this can fail, the same reasoning ResetPasswordAsync uses: an
        // invalid token and a spent one are the same answer to whoever is holding it.
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now)
        {
            logger.LogWarning("Invitation completion refused: the token is unknown, already used or expired.");
            return AccountResult.Failure("That invitation link is no longer valid.");
        }

        var errors = await validator.ValidateAsync(password, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var user = await users.FindByIdAsync(stored.UserId, cancellationToken);
        if (user is null)
            return AccountResult.Failure("That invitation link is no longer valid.");

        var trimmedUserName = userName.Trim();

        try
        {
            await credentials.CreateAsync(BuildCredential(user.Id, trimmedUserName, user.Email, password, now), cancellationToken);
        }
        catch (PasswordIdentifierConflictException)
        {
            // The reservation survives a taken user name untouched: the token is still unconsumed
            // and nothing was written to the user row, so the same person can simply try again.
            logger.LogInformation("Invitation completion refused: the user name is already in use.");
            return AccountResult.Taken("That user name is already in use.");
        }

        await users.SetUserNameAsync(user.Id, trimmedUserName, cancellationToken);
        await invitationTokens.MarkConsumedAsync(stored.Id, now, cancellationToken);

        logger.LogInformation("Invitation completed for user {UserId}.", user.Id);

        var tokens = await signIn.SignInAsync(
            new PasswordSignInRequest { Identifier = trimmedUserName, Password = password },
            cancellationToken);

        return new AccountResult { Succeeded = true, UserId = user.Id, Tokens = tokens.Tokens };
    }

    public async Task<PasswordResetRequestOutcome> RequestPasswordResetAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        var normalized = Normalizer.NormalizeOptional(email);
        if (normalized is null)
            return PasswordResetRequestOutcome.UnknownEmail;

        var credential = await credentials.FindByNormalizedEmailAsync(normalized, cancellationToken);

        if (credential is null)
        {
            // Told apart in the log and nowhere else. A person whose account is owned by an
            // identity provider will otherwise sit waiting for an email that is never coming, and
            // this line is the only way anyone diagnoses that.
            var known = await users.FindByEmailAsync(email.Trim(), cancellationToken);

            if (known is not null)
            {
                logger.LogInformation(
                    "Password reset requested for user {UserId}, which has no local credential - an identity provider owns it. "
                    + "No email sent; the person should reset with their provider.",
                    known.Id);

                return PasswordResetRequestOutcome.NoLocalCredential;
            }

            logger.LogInformation("Password reset requested for an address with no account. Nothing sent.");
            return PasswordResetRequestOutcome.UnknownEmail;
        }

        var user = await users.FindByIdAsync(credential.UserId, cancellationToken);
        if (user is null)
            return PasswordResetRequestOutcome.UnknownEmail;

        if (options.Value.RequireVerifiedEmailForPasswordReset && credential.EmailConfirmedAt is null)
        {
            // Told apart in the log and nowhere else, the same as the two cases above. This is the
            // one that looks like a bug from the outside: the account exists, it is local, and no
            // mail arrives - so the line has to say which option did it.
            logger.LogInformation(
                "Password reset requested for user {UserId}, whose email address has never been verified, and "
                + "LocalLogin:RequireVerifiedEmailForPasswordReset is on. No email sent; the address has to be "
                + "verified at /auth/email first.",
                credential.UserId);

            return PasswordResetRequestOutcome.EmailNotVerified;
        }

        var now = timeProvider.GetUtcNow();

        // Asking for a new link retires the old ones, so a forwarded email cannot be spent later.
        await resetTokens.InvalidateAllForUserAsync(credential.UserId, now, cancellationToken);

        var raw = SecureTokens.Create();

        await resetTokens.CreateAsync(
            new ToamaisutaaPasswordResetToken
            {
                Id = Guid.CreateVersion7(now),
                UserId = credential.UserId,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.PasswordResetTokenLifetime,
            },
            cancellationToken);

        try
        {
            await notifier.SendAsync(user, raw, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A real notifier can fail for reasons that have nothing to do with the account: a
            // provider outage, a rate limit, an expired credential. None of that may reach the
            // caller as anything but 204 - an unhandled exception here would answer 500 for this
            // address and 204 for an unknown one, which is exactly the distinction "always 204" was
            // meant to erase.
            logger.LogError(ex, "Password reset notifier failed for user {UserId}. The token was issued; no email was sent.", credential.UserId);
            return PasswordResetRequestOutcome.NotificationFailed;
        }

        logger.LogInformation("Password reset token issued for user {UserId} and handed to the notifier.", credential.UserId);
        return PasswordResetRequestOutcome.Sent;
    }

    public async Task<AccountResult> ResetPasswordAsync(string resetToken, string newPassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resetToken);

        var now = timeProvider.GetUtcNow();
        var stored = await resetTokens.FindByHashAsync(SecureTokens.HashToken(resetToken), cancellationToken);

        // One message for every way this can fail: an invalid token and a spent one are the same
        // answer to whoever is holding it.
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now)
        {
            logger.LogWarning("Password reset refused: the token is unknown, already used or expired.");
            return AccountResult.Failure("That reset link is no longer valid. Request a new one.");
        }

        var errors = await validator.ValidateAsync(newPassword, cancellationToken);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var credential = await credentials.FindByUserIdAsync(stored.UserId, cancellationToken);
        if (credential is null)
            return AccountResult.Failure("That reset link is no longer valid. Request a new one.");

        ApplyNewPassword(credential, newPassword, now);
        await credentials.UpdateAsync(credential, cancellationToken);

        await resetTokens.MarkConsumedAsync(stored.Id, now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(stored.UserId, now, cancellationToken);
        await emailVerificationTokens.InvalidateAllForUserAsync(stored.UserId, now, cancellationToken);

        // Nothing on the external side is touched: the external logins stay linked, and a token the
        // identity provider issued keeps working until it expires, because we cannot revoke it.
        await users.UpdateSecurityStampAsync(stored.UserId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(stored.UserId, "password-reset", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(stored.UserId, "password-reset", now, cancellationToken);

        await events.PublishAsync(new PasswordReset { OccurredAt = now, UserId = stored.UserId }, cancellationToken);

        logger.LogInformation("Password reset completed for user {UserId}; all local sessions revoked.", stored.UserId);
        return new AccountResult { Succeeded = true, UserId = stored.UserId };
    }

    /// <summary>
    /// Ends every session and publishes it, so the reason written to the rows and the reason an
    /// audit sink is handed are one string rather than two literals free to drift apart.
    /// </summary>
    private async Task RevokeAllSessionsAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await refreshTokens.RevokeAllForUserAsync(userId, reason, now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked { OccurredAt = now, UserId = userId, Reason = reason },
            cancellationToken);
    }

    private ToamaisutaaPasswordCredential BuildCredential(Guid userId, string userName, string? email, string password, DateTimeOffset now) =>
        new()
        {
            UserId = userId,
            UserName = userName,
            NormalizedUserName = Normalizer.Normalize(userName),
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            NormalizedEmail = Normalizer.NormalizeOptional(email),
            PasswordHash = hasher.Hash(password),
            CreatedAt = now,
            UpdatedAt = now,
        };

    private void ApplyNewPassword(ToamaisutaaPasswordCredential credential, string newPassword, DateTimeOffset now)
    {
        credential.PasswordHash = hasher.Hash(newPassword);
        credential.UpdatedAt = now;

        // Whoever just proved they own the account should not still be locked out of it.
        LockoutPolicy.RegisterSuccess(credential);
    }

    /// <summary>
    /// Not a constructor dependency on purpose: <see cref="IAdminPasswordIssuedNotifier"/> is
    /// optional, unlike <see cref="IPasswordResetNotifier"/>. An application that never provisions
    /// accounts on someone else's behalf should not have to register one just to use local login at
    /// all - so the failure, when it happens, happens here, at the one call site that actually needs
    /// it, rather than at startup for everyone.
    /// </summary>
    private IAdminPasswordIssuedNotifier ResolveAdminPasswordNotifier() =>
        serviceProvider.GetService<IAdminPasswordIssuedNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IAdminPasswordIssuedNotifier)} is registered. An admin-issued password is handed to it "
            + "and never returned from this call - register one before calling AdminCreateAccountAsync or "
            + "AdminSetPasswordAsync.");

    /// <summary>Same reasoning as <see cref="ResolveAdminPasswordNotifier"/>: optional, resolved
    /// lazily, and only required at the one call site that actually needs it.</summary>
    private IEmailVerificationNotifier ResolveEmailVerificationNotifier() =>
        serviceProvider.GetService<IEmailVerificationNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IEmailVerificationNotifier)} is registered. A verification token is handed to it and never "
            + "returned from this call - register one before calling RequestEmailChangeAsync.");

    /// <summary>Same reasoning as <see cref="ResolveAdminPasswordNotifier"/>: optional, resolved
    /// lazily, and only required at the one call site that actually needs it.</summary>
    private IMagicLinkNotifier ResolveMagicLinkNotifier() =>
        serviceProvider.GetService<IMagicLinkNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IMagicLinkNotifier)} is registered. A magic-link token is handed to it and never returned "
            + "from this call - register one before calling RequestMagicLinkAsync.");

    /// <summary>Same reasoning as <see cref="ResolveAdminPasswordNotifier"/>: optional, resolved
    /// lazily, and only required at the one call site that actually needs it.</summary>
    private IInvitationNotifier ResolveInvitationNotifier() =>
        serviceProvider.GetService<IInvitationNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IInvitationNotifier)} is registered. An invitation token is handed to it and never "
            + "returned from this call - register one before calling CreateInvitationAsync.");
}
