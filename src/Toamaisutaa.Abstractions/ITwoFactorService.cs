namespace Toamaisutaa.Abstractions;

/// <summary>
/// Enrolment and its ceremony. Available to any authenticated user, whether they proved themselves
/// with a password or with an identity provider's token: a second factor is a property of the
/// person, not of how they proved the first one.
/// </summary>
public interface ITwoFactorService
{
    Task<TwoFactorStatus> GetStatusAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a secret and stores it UNCONFIRMED. Deliberately does not enable anything - see
    /// <see cref="ConfirmEnrolmentAsync"/>.
    /// </summary>
    Task<TwoFactorEnrolmentStarted> BeginEnrolmentAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enables the second factor, and only now, once the user has proved the authenticator actually
    /// holds the secret. Returns the recovery codes, which are shown exactly once.
    /// </summary>
    Task<TwoFactorEnrolmentCompleted> ConfirmEnrolmentAsync(Guid userId, string code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requires a current TOTP code or a recovery code. An authenticated session is not enough: a
    /// stolen access token must not be able to switch off the second factor.
    /// </summary>
    Task<TwoFactorResult> DisableAsync(Guid userId, string proof, CancellationToken cancellationToken = default);

    /// <summary>Invalidates every previous code. Same proof requirement as disabling.</summary>
    Task<TwoFactorEnrolmentCompleted> RegenerateRecoveryCodesAsync(Guid userId, string proof, CancellationToken cancellationToken = default);
}

public sealed record TwoFactorStatus(bool Enabled, bool EnrolmentPending, int RecoveryCodesRemaining);

public sealed record TwoFactorEnrolmentStarted
{
    /// <summary>Base32, for someone typing it in by hand.</summary>
    public required string Secret { get; init; }

    /// <summary>An <c>otpauth://</c> URI. Render it as a QR code yourself - drawing one would mean a
    /// graphics dependency, and this package does not take dependencies it can avoid.</summary>
    public required string Uri { get; init; }
}

public sealed record TwoFactorEnrolmentCompleted
{
    /// <summary>Shown exactly once. They are stored hashed, so they cannot be shown again.</summary>
    public required IReadOnlyList<string> RecoveryCodes { get; init; }
}

public sealed record TwoFactorResult
{
    public required bool Succeeded { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Set when a recovery code was spent and few remain, so the application can prompt for
    /// regeneration before somebody runs out and needs a support ticket.</summary>
    public bool RecoveryCodesRunningLow { get; init; }

    public static TwoFactorResult Failure(params string[] errors) => new() { Succeeded = false, Errors = errors };
}

/// <summary>
/// An enrolment step that cannot proceed. The message reaches the person enrolling, who is already
/// authenticated and working on their own account, so it can say exactly what is wrong without
/// telling anyone something they did not already have.
/// </summary>
public sealed class TwoFactorEnrolmentException(string message) : Exception(message);
