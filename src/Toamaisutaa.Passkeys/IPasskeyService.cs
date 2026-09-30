using System.Text.Json;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// The two WebAuthn ceremonies and the credential list behind them. Inject this instead of mapping
/// the endpoints to put your own routes, response shapes or audit trail around passkeys.
/// </summary>
public interface IPasskeyService
{
    /// <summary>
    /// Starts a registration for a user who is already signed in. Nothing is stored against the
    /// account until <see cref="CompleteRegistrationAsync"/>.
    /// </summary>
    /// <param name="userId">Whose account the credential would be added to.</param>
    /// <param name="proof">
    /// The current password, or a session that presented a second factor recently. Being signed in
    /// is not enough: a passkey signs in on its own, so adding one is adding a credential.
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
    /// Starts a sign-in. Takes no identifier, so it cannot answer "does this account exist": the
    /// browser finds a discoverable credential and the assertion says whose it is.
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
    /// <remarks>
    /// Takes the same proof registering does, and throws <see cref="PasskeyRegistrationException"/>
    /// without it, since a bearer token alone could delete every passkey on a passwordless account and
    /// lock the owner out. Deleting one also moves the security stamp and ends every session, since
    /// nothing records which of them the deleted key opened.
    /// </remarks>
    Task<bool> DeleteAsync(Guid userId, Guid passkeyId, PasskeyRegistrationProof proof, CancellationToken cancellationToken = default);
}

/// <summary>
/// A ceremony the browser can now be handed.
/// </summary>
/// <remarks>
/// <see cref="Challenge"/> is opaque random bytes naming the server-held options, not the WebAuthn
/// challenge itself: a client able to hand the options back would be marking its own work.
/// </remarks>
public sealed record PasskeyCeremonyStarted
{
    public required string Challenge { get; init; }

    /// <summary>Seconds until the challenge expires.</summary>
    public required int ExpiresIn { get; init; }

    /// <summary>
    /// The WebAuthn options, as the specification defines them, ready to be passed to
    /// <c>navigator.credentials</c> after the base64url fields are decoded.
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

    /// <summary>True for a passkey the user's provider is syncing across their devices.</summary>
    public required bool IsBackedUp { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Null when it has never signed anything.</summary>
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
/// A registration step that cannot proceed. The message reaches the authenticated account owner, so
/// it can say exactly what is wrong.
/// </summary>
public sealed class PasskeyRegistrationException(string message) : Exception(message);
