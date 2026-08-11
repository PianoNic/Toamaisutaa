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
