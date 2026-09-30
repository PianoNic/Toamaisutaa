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

        if (!string.IsNullOrWhiteSpace(request.Email) && !IsBareAddress(request.Email))
            return AccountResult.Failure(NotABareAddress);

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
            // The user row already exists and now owns nothing; left behind, empty accounts accumulate.
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

            // No email on the credential: the provider's address is unproven, and copying it in would
            // make it a login identifier and reset address for a mailbox the account may not own.
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

        if (!string.IsNullOrWhiteSpace(email) && !IsBareAddress(email))
            return AccountResult.Failure(NotABareAddress);

        if (password is null && string.IsNullOrWhiteSpace(email))
            return AccountResult.Failure(NowhereToDeliver);

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
            await users.DeleteAsync(user.Id, cancellationToken);
            logger.LogInformation("Admin account creation refused: the user name or email is already in use.");
            return AccountResult.Taken("That user name or email address is already in use.");
        }

        // The plaintext password goes only to the notifier: never returned and never logged.
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

        // Only the credential's address: the profile field is written by an identity provider and
        // falling back to it mails a plaintext password to whoever controls that.
        var mailTo = credential?.Email;

        // Refused before anything changes: a generated password nobody receives, set over passkeys
        // it deletes, leaves the account with no way in.
        if (mailTo is null && password is null)
        {
            logger.LogInformation("Admin password refused for user {UserId}: no password given and no address to send a generated one to.", userId);
            return AccountResult.Failure(NowhereToDeliver);
        }

        // The password travels in the clear, so the self-service reset rule applies, checked before
        // anything is changed.
        if (mailTo is not null && options.Value.RequireVerifiedEmailForPasswordReset && credential!.EmailConfirmedAt is null)
        {
            logger.LogInformation(
                "Admin password refused for user {UserId}: the address has never been verified and "
                + "LocalLogin:RequireVerifiedEmailForPasswordReset is on.",
                userId);

            return AccountResult.Failure(
                "This account's email address has never been verified, and LocalLogin:RequireVerifiedEmailForPasswordReset "
                + "is on, so a password cannot be mailed to it. Have the owner verify the address first.");
        }

        if (credential is null)
        {
            var identifier = SignInName(user);
            if (identifier is null)
                return AccountResult.Failure(NoSignInName);

            try
            {
                // No email on the credential: the provider's address is unproven.
                await credentials.CreateCheckedAsync(BuildCredential(userId, identifier.Trim(), email: null, effectivePassword, now), cancellationToken);
            }
            catch (PasswordIdentifierConflictException)
            {
                return AccountResult.Failure("Another local account already uses that user name or email address.");
            }
        }
        else
        {
            await ApplyNewPasswordAsync(credential, effectivePassword, now, cancellationToken);
        }

        // Ahead of the notifier: the hash is already committed, and a throwing notifier must not
        // leave the sessions, devices and links of the person being locked out alive.
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
            // The password is set and cannot be undone, so the caller is told: a generated password
            // that reached nobody leaves the account unopenable.
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

        if (!IsBareAddress(newEmail))
            return AccountResult.Failure(NotABareAddress);

        var user = await users.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return AccountResult.Failure("That account no longer exists.");

        var verificationNotifier = ResolveEmailVerificationNotifier();
        var credential = await credentials.FindByUserIdAsync(userId, cancellationToken);

        if (credential is null)
        {
            return AccountResult.Failure("This account has no local password, so its email address is not ours to change.");
        }

        if (await CheckCurrentPasswordAsync(credential, currentPassword, "Email change", timeProvider.GetUtcNow(), cancellationToken) is { } refusal)
            return AccountResult.Failure(refusal);

        var trimmed = newEmail.Trim();
        var normalized = Normalizer.Normalize(trimmed);

        // Checked here as well as on redemption so no unusable link is mailed. An address held but
        // unproven by another account is not refused: redeeming this link proves it and releases theirs.
        if (await IsHeldFirmlyByAnotherAsync(normalized, userId, cancellationToken))
        {
            logger.LogInformation("Email change refused for user {UserId}: another local account already uses that address.", userId);
            return AccountResult.Taken("That email address is already in use.");
        }

        var now = timeProvider.GetUtcNow();

        // Only the most recent request can be redeemed.
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

        // One message for every way this can fail, as in ResetPasswordAsync.
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now)
        {
            logger.LogWarning("Email verification refused: the token is unknown, already used or expired.");
            return AccountResult.Failure("That verification link is no longer valid. Request a new one.");
        }

        var credential = await credentials.FindByUserIdAsync(stored.UserId, cancellationToken);
        if (credential is null)
            return AccountResult.Failure("That verification link is no longer valid. Request a new one.");

        var normalized = Normalizer.Normalize(stored.Email);

        // Re-checked because someone may have taken the address while the link sat in a mailbox; an
        // unproven hold gives way, since redeeming the link proves the mailbox.
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

        // A reset or magic link in the old mailbox is still a way in.
        await RetireOutstandingLinksAsync(stored.UserId, now, cancellationToken);

        // Sessions stay alive: proving an address is not a credential change.
        await users.SetEmailAsync(stored.UserId, stored.Email, cancellationToken);

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
            // Told apart in the log only: a caller who can tell the cases apart can enumerate addresses.
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

        // Not optional, unlike for reset: this link is exchanged for a session, so an unproven
        // address is an account handed over.
        if (credential.EmailConfirmedAt is null)
        {
            logger.LogInformation(
                "Magic link requested for user {UserId}, whose email address has never been verified. No email sent; "
                + "the address has to be verified at /auth/email first.",
                credential.UserId);

            return MagicLinkRequestOutcome.EmailNotVerified;
        }

        var now = timeProvider.GetUtcNow();

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
            // A 500 for a real address against 204 for an unknown one would enumerate accounts. The
            // filter checks this request's token because a relay timeout also raises TaskCanceledException.
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

        if (!IsBareAddress(email))
            return AccountResult.Failure(NotABareAddress);

        var invitationNotifier = ResolveInvitationNotifier();
        var now = timeProvider.GetUtcNow();

        // Reuses an open invitation and retires its earlier links, so a leaked earlier link stops working.
        var existing = await FindReservationAsync(email, now, cancellationToken);

        var user = existing ?? await users.CreateAsync(
            new ToamaisutaaUser
            {
                Email = email.Trim(),
                SecurityStamp = SecureTokens.Create(),
            },
            cancellationToken);

        if (existing is not null)
        {
            await invitationTokens.InvalidateAllForUserAsync(existing.Id, now, cancellationToken);

            // With its own links retired, anything still found is a duplicate an earlier race made.
            while (await FindReservationAsync(email, now, cancellationToken) is { } duplicate)
                await RemoveReservationAsync(duplicate.Id, now, cancellationToken);
        }

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
            // Token burnt before the row goes, so a store that does not cascade the delete still
            // leaves nothing redeemable.
            await invitationTokens.MarkConsumedAsync(tokenId, now, cancellationToken);

            // Only a row this call created; an existing reservation stays for the retry to find.
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
        var revoked = false;

        // Every reservation, not the newest: two invitations racing each made one, and the older
        // link would outlive a revoke that stopped at the first.
        while (await FindReservationAsync(email, now, cancellationToken) is { } reservation)
        {
            await RemoveReservationAsync(reservation.Id, now, cancellationToken);
            logger.LogInformation("Invitation for user {UserId} revoked, and the reserved account removed.", reservation.Id);
            revoked = true;
        }

        return revoked;
    }

    // Tokens first, so a store that does not cascade the delete still leaves nothing redeemable.
    private async Task RemoveReservationAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await invitationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await users.DeleteAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Found through the invitation token, never inferred from a user row's shape: an identity
    /// provider's account with no user name and no password looks exactly like a reservation.
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

        // One message for every way this can fail, as in ResetPasswordAsync.
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

        // Off the token: the profile email can be rewritten by an identity provider's sync.
        var invited = stored.Email ?? user.Email;

        // The returned invitation proves the mailbox, so it is verified and an unproven hold gives way.
        var credential = BuildCredential(user.Id, trimmedUserName, invited, password, now);

        // Checked before the token is spent, so a taken name leaves the link usable.
        if (await credentials.IsTakenByAnotherAsync(user.Id, credential.NormalizedUserName, cancellationToken)
            || (credential.NormalizedEmail is { } address && await IsHeldFirmlyByAnotherAsync(address, user.Id, cancellationToken)))
        {
            logger.LogInformation("Invitation completion refused: the user name or the invited address is already in use.");
            return AccountResult.Taken("That user name or email address is already in use.");
        }

        // Spent before the account is created, and only by whoever wins the write.
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
            // Told apart in the log and nowhere else; the log is how a provider-owned account waiting
            // for a reset email gets diagnosed.
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
            // From outside this looks like a bug, so the log line names the option responsible.
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
            // A 500 for a real address against 204 for an unknown one would enumerate accounts. The
            // filter checks this request's token because a relay timeout also raises TaskCanceledException.
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

        // One message for every way this can fail, so the answer reveals nothing about the token.
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

        // Spent before the password moves, and only by whoever wins the write, so concurrent
        // requests cannot each set a password.
        if (!await resetTokens.MarkConsumedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning("Password reset refused for user {UserId}: the link was spent by another request.", stored.UserId);
            return AccountResult.Failure("That reset link is no longer valid. Request a new one.");
        }

        await ApplyNewPasswordAsync(credential, newPassword, now, cancellationToken);

        await RetireOutstandingLinksAsync(stored.UserId, now, cancellationToken);

        await users.UpdateSecurityStampAsync(stored.UserId, SecureTokens.Create(), cancellationToken);
        await RevokeAllSessionsAsync(stored.UserId, "password-reset", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(stored.UserId, "password-reset", now, cancellationToken);
        await RevokeAllPasskeysAsync(stored.UserId, "password-reset", cancellationToken);

        await events.PublishAsync(new PasswordReset { OccurredAt = now, UserId = stored.UserId }, cancellationToken);

        logger.LogInformation("Password reset completed for user {UserId}; all local sessions revoked.", stored.UserId);
        return new AccountResult { Succeeded = true, UserId = stored.UserId };
    }

    /// <summary>
    /// A passkey signs in on its own, so one registered by an intruder would outlive everything else
    /// revoked here. Resolved lazily because the passkey package is optional.
    /// </summary>
    private async Task RevokeAllPasskeysAsync(Guid userId, string reason, CancellationToken cancellationToken)
    {
        var passkeys = serviceProvider.GetService<IPasskeyCredentialStore>();

        if (passkeys is null)
            return;

        var removed = await passkeys.DeleteAllAsync(userId, cancellationToken);

        if (removed > 0)
            logger.LogInformation("Deleted {Passkeys} passkey(s) for user {UserId} on {Reason}.", removed, userId, reason);
    }

    private async Task RevokeAllSessionsAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await refreshTokens.RevokeAllForUserAsync(userId, reason, now, cancellationToken);

        await events.PublishAsync(
            new SessionRevoked { OccurredAt = now, UserId = userId, Reason = reason },
            cancellationToken);
    }

    // An address-shaped user name would hold that address in a column proving the mailbox cannot release.
    private const string AddressShapedUserName = "A user name cannot contain @. An email address goes in the email field.";

    private const string NoSignInName =
        "This account has no user name to sign in with. An email address from an identity provider cannot stand in for one, "
        + "because nothing here has proved it.";

    private static bool IsAddressShaped(string userName) => userName.Contains('@');

    // A display name in front of the address would carry arbitrary text from this domain to any inbox.
    private const string NotABareAddress = "Give just the email address, with nothing around it.";

    private const string NowhereToDeliver =
        "This account has no local email address to send a generated password to. Give the password in the request "
        + "and deliver it yourself.";

    private static bool IsBareAddress(string email) =>
        System.Net.Mail.MailAddress.TryCreate(email.Trim(), out var parsed)
        && parsed.DisplayName.Length == 0
        && string.Equals(parsed.Address, email.Trim(), StringComparison.Ordinal);

    // Never the email: it is only what an identity provider asserted.
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
    /// Every kind of mailed link must be here: one left out still signs in after the account has been secured.
    /// </summary>
    private async Task RetireOutstandingLinksAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await magicLinkTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
        await emailVerificationTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);
    }

    /// <summary>
    /// A proven claim outranks an unproven hold, or anybody could register someone else's address first
    /// and lock the real owner out.
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
    /// An unverified email hold does not count, because verifying releases it.
    /// </summary>
    private async Task<bool> IsHeldFirmlyByAnotherAsync(string normalizedEmail, Guid userId, CancellationToken cancellationToken)
    {
        var holder = await credentials.FindByIdentifierAsync(normalizedEmail, cancellationToken);

        if (holder is null || holder.UserId == userId)
            return false;

        return holder.NormalizedEmail != normalizedEmail || holder.EmailConfirmedAt is not null;
    }

    /// <summary>
    /// Addressed to the credential's email, not the profile field an identity provider's sync writes,
    /// so links go to the address that was checked. A copy, so the profile is never written.
    /// </summary>
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

    // replacing is the hash the current password was checked against; a retry finding another hash
    // lost a race with a reset and must not overwrite it. Null replaces unconditionally.
    private async Task<bool> ApplyNewPasswordAsync(
        ToamaisutaaPasswordCredential credential,
        string newPassword,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        string? replacing = null)
    {
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

                LockoutPolicy.RegisterSuccess(current);
            },
            cancellationToken);

        return replaced;
    }

    /// <summary>
    /// Resolved lazily because the notifier is optional; only the call site that needs it fails.
    /// </summary>
    private IAdminPasswordIssuedNotifier ResolveAdminPasswordNotifier() =>
        serviceProvider.GetService<IAdminPasswordIssuedNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IAdminPasswordIssuedNotifier)} is registered. An admin-issued password is handed to it "
            + "and never returned from this call - register one before calling AdminCreateAccountAsync or "
            + "AdminSetPasswordAsync.");

    private IEmailVerificationNotifier ResolveEmailVerificationNotifier() =>
        serviceProvider.GetService<IEmailVerificationNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IEmailVerificationNotifier)} is registered. A verification token is handed to it and never "
            + "returned from this call - register one before calling RequestEmailChangeAsync.");

    private IMagicLinkNotifier ResolveMagicLinkNotifier() =>
        serviceProvider.GetService<IMagicLinkNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IMagicLinkNotifier)} is registered. A magic-link token is handed to it and never returned "
            + "from this call - register one before calling RequestMagicLinkAsync.");

    private IInvitationNotifier ResolveInvitationNotifier() =>
        serviceProvider.GetService<IInvitationNotifier>()
        ?? throw new InvalidOperationException(
            $"No {nameof(IInvitationNotifier)} is registered. An invitation token is handed to it and never "
            + "returned from this call - register one before calling CreateInvitationAsync.");
}
