using System.Text.Json;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// The two WebAuthn ceremonies and the credential list behind them.
/// </summary>
/// <remarks>
/// Public for the reason <see cref="ITrustedDeviceService"/> is: an application that wants its own
/// routes, its own response shapes or its own audit trail around passkeys injects this instead of
/// mapping the endpoints, and the alternative is reimplementing a ceremony that has to be exactly
/// right to be worth anything.
/// </remarks>
public interface IPasskeyService
{
    /// <summary>
    /// Starts a registration for a user who is already signed in. Nothing is stored against the
    /// account until <see cref="CompleteRegistrationAsync"/>.
    /// </summary>
    /// <param name="userId">Whose account the credential would be added to.</param>
    /// <param name="proof">
    /// The current password, or a session that presented a second factor recently. Being signed in
    /// is not enough on its own: a passkey signs in with no password and no code, so adding one is
    /// adding a credential rather than changing a setting.
    /// </param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <exception cref="PasskeyRegistrationException">The proof is missing or wrong.</exception>
    Task<PasskeyCeremonyStarted> BeginRegistrationAsync(
        Guid userId,
        PasskeyRegistrationProof proof,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies what the authenticator produced and stores the credential.</summary>
    Task<PasskeySummary> CompleteRegistrationAsync(
        Guid userId,
        PasskeyRegistrationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts a sign-in. Takes no identifier: the browser finds a discoverable credential itself and
    /// the assertion says who it belongs to, so there is nothing here to answer "does this account
    /// exist" to whoever asked.
    /// </summary>
    Task<PasskeyCeremonyStarted> BeginAssertionAsync(CancellationToken cancellationToken = default);

    /// <summary>Verifies an assertion and, if it holds, issues the session it earned.</summary>
    Task<PasskeySignInResult> CompleteAssertionAsync(
        PasskeyAssertionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Newest first, so the one just registered is at the top.</summary>
    Task<IReadOnlyList<PasskeySummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>False when the credential does not exist or belongs to someone else - the same
    /// answer, so this cannot be used to discover another account's credential ids.</summary>
    Task<bool> DeleteAsync(Guid userId, Guid passkeyId, CancellationToken cancellationToken = default);
}

/// <summary>
/// A ceremony the browser can now be handed.
/// </summary>
/// <remarks>
/// <see cref="Challenge"/> names the server's half of it and is what comes back to complete it. It
/// is opaque random bytes rather than the WebAuthn challenge itself: the options carry rules the
/// completion step checks the authenticator against, so a client able to hand them back would be
/// marking its own work.
/// </remarks>
public sealed record PasskeyCeremonyStarted
{
    public required string Challenge { get; init; }

    /// <summary>Seconds until the challenge expires.</summary>
    public required int ExpiresIn { get; init; }

    /// <summary>
    /// The WebAuthn options, ready to be passed to <c>navigator.credentials</c> after the base64url
    /// fields are decoded. Passed through as JSON rather than remodelled: this is a shape the
    /// specification defines and every client library already knows, and a second model of it here
    /// would be a translation that can drift.
    /// </summary>
    public required JsonElement Options { get; init; }
}

/// <summary>One registered credential, as its owner sees it in a list.</summary>
public sealed record PasskeySummary
{
    /// <summary>The row id. Pass it back to delete. Deliberately not the credential id the
    /// authenticator uses, which is a value the sign-in path matches on.</summary>
    public required Guid Id { get; init; }

    /// <summary>What the user called it. Null until they name one.</summary>
    public string? Label { get; init; }

    /// <summary>How the authenticator can be reached - <c>usb</c>, <c>internal</c> and the rest.
    /// Empty when it did not say.</summary>
    public IReadOnlyList<string> Transports { get; init; } = [];

    /// <summary>True for a passkey the user's provider is syncing across their devices. Worth
    /// showing: it is the difference between losing the laptop and losing the account.</summary>
    public required bool IsBackedUp { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Null when it has never signed anything, which is the most useful thing a list can
    /// say about a credential somebody is deciding whether to delete.</summary>
    public DateTimeOffset? LastUsedAt { get; init; }
}

/// <summary>What a completed assertion came to.</summary>
public sealed record PasskeySignInResult
{
    public required SignInOutcome Outcome { get; init; }

    public TokenPair? Tokens { get; init; }

    /// <summary>
    /// Set with <see cref="SignInOutcome.TwoFactorRequired"/>, when the assertion proved possession
    /// alone and the account carries a confirmed enrolment. Present it with a code to
    /// <c>/auth/2fa/verify</c>, exactly as a password sign-in's challenge is presented.
    /// </summary>
    public TwoFactorChallenge? Challenge { get; init; }

    public bool Succeeded => Outcome == SignInOutcome.Succeeded;
}

/// <summary>
/// A registration step that cannot proceed. The message reaches somebody already authenticated and
/// working on their own account, so it can say exactly what is wrong.
/// </summary>
public sealed class PasskeyRegistrationException(string message) : Exception(message);
