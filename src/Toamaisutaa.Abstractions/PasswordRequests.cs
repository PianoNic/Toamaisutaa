namespace Toamaisutaa.Abstractions;

/// <summary>
/// <see cref="Identifier"/> is a user name or an email address. <see cref="DeviceToken"/> is
/// optional: send one from a previously trusted device to skip the two-factor challenge.
/// </summary>
public sealed record LoginRequest(string Identifier, string Password, string? DeviceToken = null);

public sealed record RefreshRequest(string RefreshToken);

public sealed record LogoutRequest(string RefreshToken);

public sealed record RegisterRequest(string UserName, string? Email, string Password);

/// <summary><see cref="CurrentPassword"/> is required when the account already has one, and must be
/// absent when it does not - which is the case for an account that arrived through an identity
/// provider and is adding a password for the first time.</summary>
public sealed record ChangePasswordRequest(string? CurrentPassword, string NewPassword);

public sealed record ForgotPasswordRequest(string Email);

public sealed record ResetPasswordRequest(string Token, string NewPassword);

/// <summary><see cref="Password"/> is optional - omit it and Toamaisutaa generates one, handed to
/// <see cref="IAdminPasswordIssuedNotifier"/> rather than returned from the endpoint.</summary>
public sealed record CreateUserRequest(string UserName, string? Email, string? Password);

/// <summary><see cref="Password"/> is optional - omit it and Toamaisutaa generates one, handed to
/// <see cref="IAdminPasswordIssuedNotifier"/> rather than returned from the endpoint.</summary>
public sealed record SetUserPasswordRequest(string? Password);

/// <summary><see cref="CurrentPassword"/> is always required, including when
/// <see cref="NewEmail"/> is the address the account already has - which is how a verification link
/// is asked for again.</summary>
public sealed record ChangeEmailRequest(string NewEmail, string CurrentPassword);

public sealed record VerifyEmailRequest(string Token);

/// <summary>The address a magic link is asked for. Answered identically whether or not it belongs to
/// anybody, so nothing here is validated back to the caller.</summary>
public sealed record MagicLinkRequest(string Email);

public sealed record VerifyMagicLinkRequest(string Token);

public sealed record CreateInvitationRequest(string Email);

public sealed record CompleteInvitationRequest(string Token, string UserName, string Password);
