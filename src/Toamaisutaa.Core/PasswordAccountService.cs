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
    IPasswordHasher hasher,
    IPasswordValidator validator,
    IPasswordResetNotifier notifier,
    IPasswordSignInService signIn,
    TrustedDeviceGate trustedDevices,
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

        var errors = validator.Validate(request.Password);
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

        var errors = validator.Validate(newPassword);
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
        await refreshTokens.RevokeAllForUserAsync(userId, "password-changed", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "password-changed", now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

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

        var errors = validator.Validate(effectivePassword);
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

        var errors = validator.Validate(effectivePassword);
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
        await refreshTokens.RevokeAllForUserAsync(userId, "admin-password-set", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(userId, "admin-password-set", now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(userId, now, cancellationToken);

        logger.LogInformation("Admin set the password for user {UserId}; all local sessions revoked.", userId);

        return new AccountResult { Succeeded = true, UserId = userId };
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

        var errors = validator.Validate(newPassword);
        if (errors.Count > 0)
            return new AccountResult { Succeeded = false, Errors = errors };

        var credential = await credentials.FindByUserIdAsync(stored.UserId, cancellationToken);
        if (credential is null)
            return AccountResult.Failure("That reset link is no longer valid. Request a new one.");

        ApplyNewPassword(credential, newPassword, now);
        await credentials.UpdateAsync(credential, cancellationToken);

        await resetTokens.MarkConsumedAsync(stored.Id, now, cancellationToken);
        await resetTokens.InvalidateAllForUserAsync(stored.UserId, now, cancellationToken);

        // Nothing on the external side is touched: the external logins stay linked, and a token the
        // identity provider issued keeps working until it expires, because we cannot revoke it.
        await users.UpdateSecurityStampAsync(stored.UserId, SecureTokens.Create(), cancellationToken);
        await refreshTokens.RevokeAllForUserAsync(stored.UserId, "password-reset", now, cancellationToken);
        await trustedDevices.RevokeAllAsync(stored.UserId, "password-reset", now, cancellationToken);

        logger.LogInformation("Password reset completed for user {UserId}; all local sessions revoked.", stored.UserId);
        return new AccountResult { Succeeded = true, UserId = stored.UserId };
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
}
