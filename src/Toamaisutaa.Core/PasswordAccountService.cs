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

        if (IsAddressShaped(request.UserName))
            return AccountResult.Failure(AddressShapedUserName);

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
            await credentials.CreateCheckedAsync(
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
        DateTimeOffset? authenticatedAt = null,
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

            // A time ahead of now is a clock problem, not a fresh sign-in.
            if (authenticatedAt is not { } at || at > now || now - at > options.Value.FirstPasswordProofWindow)
            {
                logger.LogWarning(
                    "First password refused for user {UserId}: the caller has not authenticated within the proof window.",
                    userId);

                return AccountResult.Failure(
                    "Adding a first password needs a recent sign-in. Sign in again, then add it while that sign-in is fresh.");
            }

            var userName = SignInName(user);
            if (userName is null)
                return AccountResult.Failure(NoSignInName);

            // No email on the credential. The address on the profile is whatever the identity
            // provider asserted, and nothing here knows that anybody proved it: copied in, it became
            // a login identifier and a reset address for a mailbox the account may not own, so the
            // real owner's forgot-password adopted an account somebody else's provider login still
            // opens. The address can be added through /auth/email, which proves it.
            try
            {
                await credentials.CreateCheckedAsync(
                    BuildCredential(userId, userName.Trim(), email: null, newPassword, now),
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

            var checkedHash = credential.PasswordHash;

            if (await CheckCurrentPasswordAsync(credential, currentPassword, "Password change", now, cancellationToken) is { } refusal)
                return AccountResult.Failure(refusal);

            if (!await ApplyNewPasswordAsync(credential, newPassword, now, cancellationToken, replacing: checkedHash))
            {
                logger.LogWarning("Password change refused for user {UserId}: the password was changed by another request first.", userId);
                return AccountResult.Failure("Your password was changed by another request. Sign in again and retry.");
            }

            logger.LogInformation("Changed the password for user {UserId}.", userId);
        }

        // A password change ends the other sessions. It is the one moment the account holder is
        // most likely to be reacting to someone else having access.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(userId, "password-changed", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "password-changed", now, cancellationToken);
        await RevokeAllPasskeysAsync(userId, "password-changed", cancellationToken);
        await RetireOutstandingLinksAsync(userId, now, cancellationToken);

        await events.PublishAsync(new PasswordChanged { OccurredAt = now, UserId = userId }, cancellationToken);

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

        if (IsAddressShaped(userName))
            return AccountResult.Failure(AddressShapedUserName);

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
            await credentials.CreateCheckedAsync(BuildCredential(user.Id, userName.Trim(), email, effectivePassword, now), cancellationToken);
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

        // The password travels in the clear to whatever address it is mailed to, so the rule a
        // self-service reset follows applies here too, checked before anything is changed.
        if (credential is not null && options.Value.RequireVerifiedEmailForPasswordReset && credential.EmailConfirmedAt is null)
        {
            logger.LogInformation(
                "Admin password refused for user {UserId}: the address has never been verified and "
                + "LocalLogin:RequireVerifiedEmailForPasswordReset is on.",
                userId);

            return AccountResult.Failure(
                "This account's email address has never been verified, and LocalLogin:RequireVerifiedEmailForPasswordReset "
                + "is on, so a password cannot be mailed to it. Have the owner verify the address first.");
        }

        // The address the password goes to: the credential's, which is the one the account signs in
        // with, not the profile field an identity provider's sync writes.
        var mailTo = credential?.Email ?? user.Email;

        if (credential is null)
        {
            var identifier = SignInName(user);
            if (identifier is null)
                return AccountResult.Failure(NoSignInName);

            try
            {
                // No email on the credential, for the reason a first password gets none: the
                // provider's address is only what the provider asserted.
                await credentials.CreateCheckedAsync(BuildCredential(userId, identifier.Trim(), email: null, effectivePassword, now), cancellationToken);
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
            await ApplyNewPasswordAsync(credential, effectivePassword, now, cancellationToken);
        }

        // Same reasoning as a self-service change: whoever is now holding this password should not
        // find the account's other sessions still alive. Ahead of the notifier rather than behind
        // it, because the hash is already committed by here and a notifier that throws would
        // otherwise leave every one of these undone - the account reset in order to lock somebody
        // out would keep their refresh family, their trusted devices and their reset tokens.
        await users.UpdateSecurityStampAsync(userId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(userId, "admin-password-set", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "admin-password-set", now, cancellationToken);
        await RevokeAllPasskeysAsync(userId, "admin-password-set", cancellationToken);
        await RetireOutstandingLinksAsync(userId, now, cancellationToken);

        await events.PublishAsync(
            new PasswordChanged { OccurredAt = now, UserId = userId, SetByAdministrator = true },
            cancellationToken);

        try
        {
            await adminNotifier.PasswordIssuedAsync(AddressedTo(user, mailTo), effectivePassword, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Nothing to undo and nothing to retry here: the password is set and the sessions are
            // gone. The caller is told instead, because a generated password that reached
            // nobody leaves an account only another call to this method can open.
            logger.LogError(
                ex,
                "Admin password notifier failed for user {UserId}. The password was set and all local sessions "
                + "revoked, but nothing was delivered.",
                userId);

            return new AccountResult { Succeeded = true, UserId = userId, NotificationFailed = true };
        }

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

        if (await CheckCurrentPasswordAsync(credential, currentPassword, "Email change", timeProvider.GetUtcNow(), cancellationToken) is { } refusal)
            return AccountResult.Failure(refusal);

        var trimmed = newEmail.Trim();
        var normalized = Normalizer.Normalize(trimmed);

        // Checked here as well as on redemption. Doing it only on redemption would mail a link that
        // cannot work, and the person holding it has no way to tell that from a broken link. Against
        // user names too: the sign-in box takes either, so they are one namespace. An address another
        // account holds without having proven it is not refused: redeeming this link proves it, and
        // releases theirs.
        if (await IsHeldFirmlyByAnotherAsync(normalized, userId, cancellationToken))
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
        // sentence the person can read. Redeeming the link is proof of the mailbox, so an unproven
        // hold on the address gives way to it rather than refusing it.
        if (await IsHeldFirmlyByAnotherAsync(normalized, stored.UserId, cancellationToken))
        {
            logger.LogInformation("Email verification refused for user {UserId}: another local account now uses that address.", stored.UserId);
            return AccountResult.Taken("That email address is already in use.");
        }

        // Spent before anything moves, and only by whoever wins the write.
        if (!await emailVerificationTokens.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Email verification refused for user {UserId}: the link was spent by another request.", stored.UserId);
            return AccountResult.Failure("That verification link is no longer valid. Request a new one.");
        }

        await ReleaseUnverifiedHoldAsync(normalized, stored.UserId, now, cancellationToken);

        var previousEmail = credential.Email;

        await credentials.UpdateAsync(
            credential,
            current =>
            {
                current.Email = stored.Email;
                current.NormalizedEmail = normalized;
                current.EmailConfirmedAt = now;
                current.UpdatedAt = now;
            },
            cancellationToken);

        // The address moved, so every link mailed to the old one is retired: a reset or magic link
        // sitting in a mailbox the owner just walked away from is still a way in.
        await RetireOutstandingLinksAsync(stored.UserId, now, cancellationToken);

        // The profile field follows the login identifier, so the reset and invitation notifiers stop
        // addressing mail to where this account used to be. Nothing else moves: sessions stay alive,
        // because proving an address is not a credential change.
        await users.SetEmailAsync(stored.UserId, stored.Email, cancellationToken);

        // The one account change that moves where a reset link goes, so an audit table gets a row
        // for it rather than leaving the move to be inferred from the sign-ins that follow it.
        await events.PublishAsync(
            new EmailChanged
            {
                OccurredAt = now,
                UserId = stored.UserId,
                PreviousEmail = previousEmail,
                Email = stored.Email,
            },
            cancellationToken);

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
            await magicLinkNotifier.SendAsync(AddressedTo(user, credential.Email), raw, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Same reasoning as the reset notifier: an unhandled exception here would answer 500 for
            // a real address and 204 for an unknown one, which is exactly the distinction "always
            // 204" was meant to erase. A relay that stops answering raises TaskCanceledException on
            // its own timeout, so the filter asks whether this request was cancelled rather than
            // reading a cancellation type as one.
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

        // Inviting an address that already has an open invitation reuses it and retires its earlier
        // links, so only the newest one works. Each invitation used to reserve a fresh row with a
        // fresh week-long token, and a link that leaked the first time stayed redeemable however
        // many times the address was invited since.
        var existing = await FindReservationAsync(email, now, cancellationToken);

        // No user name and no credential - the row exists to be completed, not signed into. It is
        // deliberately not a match for RegisterAsync's shape: nothing here is a finished account yet.
        var user = existing ?? await users.CreateAsync(
            new ToamaisutaaUser
            {
                Email = email.Trim(),
                SecurityStamp = SecureTokens.Create(),
            },
            cancellationToken);

        if (existing is not null)
            await invitationTokens.InvalidateAllForUserAsync(existing.Id, now, cancellationToken);

        var raw = SecureTokens.Create();
        var tokenId = Guid.CreateVersion7(now);

        await invitationTokens.CreateAsync(
            new ToamaisutaaInvitationToken
            {
                Id = tokenId,
                UserId = user.Id,
                TokenHash = SecureTokens.HashToken(raw),
                CreatedAt = now,
                ExpiresAt = now + options.Value.InvitationTokenLifetime,
                Email = email.Trim(),
                NormalizedEmail = Normalizer.Normalize(email),
            },
            cancellationToken);

        try
        {
            await invitationNotifier.SendAsync(user, raw, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Rolled back rather than reported and left, because nothing here found an existing
            // reservation before creating this one: retrying against a relay that is still down
            // would reserve the same address again, and again. The token is burnt before the row
            // goes, so a store that does not cascade the delete still leaves nothing redeemable.
            await invitationTokens.MarkConsumedAsync(tokenId, now, cancellationToken);

            // Only a row this call created. A reservation that was already there stays, with its
            // earlier links retired: the retry that follows finds it again rather than adding a row.
            if (existing is null)
                await users.DeleteAsync(user.Id, cancellationToken);

            logger.LogError(
                ex,
                existing is null
                    ? "Invitation notifier failed for user {UserId}. Nothing was sent, and the reserved account and its token were rolled back."
                    : "Invitation notifier failed for user {UserId}. Nothing was sent; the reservation stays and its earlier links are retired.",
                user.Id);

            return new AccountResult
            {
                Succeeded = false,
                NotificationFailed = true,
                Errors = [existing is null
                    ? "The invitation could not be sent, so no account was reserved."
                    : "The invitation could not be sent. Earlier links to this address no longer work; send it again once delivery works."],
            };
        }

        logger.LogInformation("Invitation created for user {UserId} and handed to the notifier.", user.Id);

        return new AccountResult { Succeeded = true, UserId = user.Id };
    }

    public async Task<bool> RevokeInvitationAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        var now = timeProvider.GetUtcNow();
        var reservation = await FindReservationAsync(email, now, cancellationToken);
        if (reservation is null)
            return false;

        // Tokens first, so a store that does not cascade the delete still leaves nothing redeemable.
        await invitationTokens.InvalidateAllForUserAsync(reservation.Id, now, cancellationToken);
        await users.DeleteAsync(reservation.Id, cancellationToken);

        logger.LogInformation("Invitation for user {UserId} revoked, and the reserved account removed.", reservation.Id);
        return true;
    }

    /// <summary>
    /// The account an open invitation to this address reserved, found through the invitation token
    /// itself. Never inferred from a user row's shape: an identity provider's account with no user
    /// name and no password looks exactly like a reservation, and that inference let an invitation
    /// adopt such an account and a revocation delete it.
    /// </summary>
    private async Task<ToamaisutaaUser?> FindReservationAsync(string email, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (Normalizer.NormalizeOptional(email) is not { } normalized)
            return null;

        if (await invitationTokens.FindOpenByEmailAsync(normalized, now, cancellationToken) is not { } open)
            return null;

        var user = await users.FindByIdAsync(open.UserId, cancellationToken);

        // Completed since: somebody's account now, and never reused or removed.
        if (user is null || user.UserName is not null || await credentials.FindByUserIdAsync(user.Id, cancellationToken) is not null)
            return null;

        return user;
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

        if (IsAddressShaped(userName))
            return AccountResult.Failure(AddressShapedUserName);

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

        // The address the invitation was sent to, off the token. The user row's profile email is
        // what an identity provider's sync writes, and could have been pointed somewhere else between
        // the invitation and now.
        var invited = stored.Email ?? user.Email;

        // The invitation went to this address and came back, which proves the mailbox. So it is
        // verified from the start, and an unproven hold on it - a registration that got there
        // first - gives way instead of turning every name the invitee tries into a 409.
        var credential = BuildCredential(user.Id, trimmedUserName, invited, password, now);

        // Checked before the token is spent, so a taken name costs the invitee nothing: they pick
        // another and the same link still works.
        if (await credentials.IsTakenByAnotherAsync(user.Id, credential.NormalizedUserName, cancellationToken)
            || (credential.NormalizedEmail is { } address && await IsHeldFirmlyByAnotherAsync(address, user.Id, cancellationToken)))
        {
            logger.LogInformation("Invitation completion refused: the user name or the invited address is already in use.");
            return AccountResult.Taken("That user name or email address is already in use.");
        }

        // Spent before the account is created, and only by whoever wins the write. Two completions
        // of one link at once used to both reach the insert, and the second answered 500.
        if (!await invitationTokens.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Invitation completion refused for user {UserId}: the link was spent by another request.", user.Id);
            return AccountResult.Failure("That invitation link is no longer valid.");
        }

        if (credential.NormalizedEmail is { } invitedAddress)
        {
            credential.EmailConfirmedAt = now;
            await ReleaseUnverifiedHoldAsync(invitedAddress, user.Id, now, cancellationToken);
        }

        try
        {
            await credentials.CreateCheckedAsync(credential, cancellationToken);
        }
        catch (PasswordIdentifierConflictException)
        {
            // Taken in the moment since the check above. The link is spent by now, so say so.
            logger.LogInformation("Invitation completion for user {UserId} lost its user name to another account at the last moment.", user.Id);
            return AccountResult.Taken("That user name or email address was taken a moment ago. Ask for a new invitation.");
        }

        await users.SetUserNameAsync(user.Id, trimmedUserName, cancellationToken);

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
            await notifier.SendAsync(AddressedTo(user, credential.Email), raw, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // A real notifier can fail for reasons that have nothing to do with the account: a
            // provider outage, a rate limit, an expired credential, a mail API that stops answering
            // until HttpClient gives up on it. None of that may reach the caller as anything but
            // 204 - an unhandled exception here would answer 500 for this address and 204 for an
            // unknown one, which is exactly the distinction "always 204" was meant to erase. The
            // timeout arrives as TaskCanceledException, so only this request's own cancellation is
            // let through.
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

        // Spent before the password moves, and only by whoever wins the write. The check above
        // and this are two steps, and every request that landed between them used to set a password.
        if (!await resetTokens.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Password reset refused for user {UserId}: the link was spent by another request.", stored.UserId);
            return AccountResult.Failure("That reset link is no longer valid. Request a new one.");
        }

        await ApplyNewPasswordAsync(credential, newPassword, now, cancellationToken);

        await RetireOutstandingLinksAsync(stored.UserId, now, cancellationToken);

        // Nothing on the external side is touched: the external logins stay linked, and a token the
        // identity provider issued keeps working until it expires, because we cannot revoke it.
        await users.UpdateSecurityStampAsync(stored.UserId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(stored.UserId, "password-reset", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(stored.UserId, "password-reset", now, cancellationToken);
        await RevokeAllPasskeysAsync(stored.UserId, "password-reset", cancellationToken);

        await events.PublishAsync(new PasswordReset { OccurredAt = now, UserId = stored.UserId }, cancellationToken);

        logger.LogInformation("Password reset completed for user {UserId}; all local sessions revoked.", stored.UserId);
        return new AccountResult { Succeeded = true, UserId = stored.UserId };
    }

    /// <summary>
    /// Deletes every passkey on the account, wherever the trusted devices go.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A passkey signs in on its own, with no password and no code, so one registered by somebody
    /// who should not have it is a way back into the account that outlives every other thing this
    /// method's callers revoke. The person changing their password is doing the one thing the
    /// package offers for exactly that, and it has to take the credentials with it.
    /// </para>
    /// <para>
    /// Resolved through the provider rather than the constructor, the way the notifiers below are:
    /// the passkey package is optional, and naming its store here would make Core require a package
    /// that references FIDO2.
    /// </para>
    /// </remarks>
    private async Task RevokeAllPasskeysAsync(Guid userId, string reason, CancellationToken cancellationToken)
    {
        var passkeys = serviceProvider.GetService<IPasskeyCredentialStore>();

        if (passkeys is null)
            return;

        var removed = await passkeys.DeleteAllAsync(userId, cancellationToken);

        if (removed > 0)
            logger.LogInformation("Deleted {Passkeys} passkey(s) for user {UserId} on {Reason}.", removed, userId, reason);
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

    // The sign-in box takes a user name or an email, and a user name shaped like an address sat in
    // the one column no proof of the mailbox could ever release: whoever registered it first owned
    // that address for sign-in, invitations and /auth/email, however the real owner proved it.
    private const string AddressShapedUserName = "A user name cannot contain @. An email address goes in the email field.";

    private const string NoSignInName =
        "This account has no user name to sign in with. An email address from an identity provider cannot stand in for one, "
        + "because nothing here has proved it.";

    private static bool IsAddressShaped(string userName) => userName.Contains('@');

    // Never the email: that is only what an identity provider asserted, and in the user-name column
    // it becomes a hold on the address that proving the mailbox cannot release.
    private static string? SignInName(ToamaisutaaUser user) =>
        string.IsNullOrWhiteSpace(user.UserName) || IsAddressShaped(user.UserName) ? null : user.UserName.Trim();

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

    /// <summary>
    /// Every link mailed out and not yet used: reset, magic and email verification. Called on each
    /// change that is somebody reacting to another person having had access - a password set, reset
    /// or changed, or the account moved to a new address. A magic link was left out of that list,
    /// and one still sitting in a mailbox signed in after the account had been secured.
    /// </summary>
    private async Task RetireOutstandingLinksAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await magicLinkTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await emailVerificationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
    }

    /// <summary>
    /// A proven claim to an address outranks an unproven hold on it. Registration takes whatever
    /// address it is typed, so without this anybody could register a new hire's address first and
    /// leave the real owner with a 409 on every way in and no way to put it right.
    /// </summary>
    private async Task ReleaseUnverifiedHoldAsync(
        string normalizedEmail,
        Guid claimant,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var holder = await credentials.FindByNormalizedEmailAsync(normalizedEmail, cancellationToken);
        if (holder is null || holder.UserId == claimant || holder.EmailConfirmedAt is not null)
            return;

        await credentials.UpdateAsync(
            holder,
            current =>
            {
                if (current.EmailConfirmedAt is not null || current.NormalizedEmail != normalizedEmail)
                    return;

                current.Email = null;
                current.NormalizedEmail = null;
                current.UpdatedAt = now;
            },
            cancellationToken);

        logger.LogWarning(
            "Released the unverified email address held by user {HolderId}: user {ClaimantId} proved they own it.",
            holder.UserId,
            claimant);
    }

    /// <summary>
    /// Whether an address is held in a way a proven claim cannot take over: as another account's user
    /// name, or as its verified email. An unverified email hold does not count - verifying releases it.
    /// </summary>
    private async Task<bool> IsHeldFirmlyByAnotherAsync(string normalizedEmail, Guid userId, CancellationToken cancellationToken)
    {
        var holder = await credentials.FindByIdentifierAsync(normalizedEmail, cancellationToken);

        if (holder is null || holder.UserId == userId)
            return false;

        return holder.NormalizedEmail != normalizedEmail || holder.EmailConfirmedAt is not null;
    }

    /// <summary>
    /// The user as a notifier should see them: addressed to the email on the credential, which is
    /// the address the request was looked up by and, for a magic link, the one that was verified.
    /// </summary>
    /// <remarks>
    /// <see cref="ToamaisutaaUser.Email"/> is the profile field, and an identity provider's profile
    /// sync writes it. Mailing that one meant the check applied to one address and the link went to
    /// another - whoever could edit the provider profile received the victim's links, and a verified
    /// move off a compromised mailbox was quietly undone by the next sync. A copy, so nothing here
    /// writes the profile.
    /// </remarks>
    private static ToamaisutaaUser AddressedTo(ToamaisutaaUser user, string? email) => new()
    {
        Id = user.Id,
        UserName = user.UserName,
        Email = email,
        DisplayName = user.DisplayName,
        PictureUrl = user.PictureUrl,
        SecurityStamp = user.SecurityStamp,
        CreatedAt = user.CreatedAt,
        UpdatedAt = user.UpdatedAt,
    };

    private Task<string?> CheckCurrentPasswordAsync(
        ToamaisutaaPasswordCredential credential,
        string currentPassword,
        string action,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        credentials.CheckCurrentPasswordAsync(credential, currentPassword, hasher, events, options.Value, logger, action, now, cancellationToken);

    // replacing is the hash the caller's current password was checked against, for a change that
    // proved one. A retry that finds another hash there has lost a race with a reset, and writing over
    // it would leave the owner holding a reset password that no longer works. Null for a reset or an
    // admin setting it, which replace whatever is there on purpose. False when it no longer matched.
    private async Task<bool> ApplyNewPasswordAsync(
        ToamaisutaaPasswordCredential credential,
        string newPassword,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        string? replacing = null)
    {
        // Hashed once, outside the retry: it is the expensive half, and the value does not depend on
        // what the row held.
        var hash = hasher.Hash(newPassword);
        var replaced = true;

        await credentials.UpdateAsync(
            credential,
            current =>
            {
                replaced = replacing is null || current.PasswordHash == replacing;

                if (!replaced)
                    return;

                current.PasswordHash = hash;
                current.UpdatedAt = now;

                // Whoever just proved they own the account should not still be locked out of it.
                LockoutPolicy.RegisterSuccess(current);
            },
            cancellationToken);

        return replaced;
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
