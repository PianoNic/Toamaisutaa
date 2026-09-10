using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>
/// A breach-list check in front of whatever validator was already registered. It adds one message
/// and removes none, so the length rules still say what they said.
/// </summary>
internal sealed class HibpPasswordValidator(
    IPasswordValidator inner,
    IBreachedPasswordIndex index,
    IOptions<ToamaisutaaHibpOptions> options,
    ILogger<HibpPasswordValidator> logger) : IPasswordValidator
{
    /// <summary>
    /// Blocks on the lookup. Nothing in the package calls this - every call site of its own uses
    /// <see cref="ValidateAsync"/> - and it exists only for a consumer holding
    /// <see cref="IPasswordValidator"/> from somewhere synchronous.
    /// </summary>
    public IReadOnlyList<string> Validate(string password) =>
        ValidateAsync(password).AsTask().GetAwaiter().GetResult();

    public async ValueTask<IReadOnlyList<string>> ValidateAsync(string password, CancellationToken cancellationToken = default)
    {
        var errors = await inner.ValidateAsync(password, cancellationToken);

        // A password the length rules already refused is not one anybody is about to end up with,
        // so there is nothing to learn by asking about it - and asking would spend a request on
        // every short password typed into an anonymous endpoint.
        if (errors.Count > 0)
            return errors;

        var settings = options.Value;
        int count;

        try
        {
            count = await index.CountAsync(password, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Fails open, deliberately. This is a second opinion on a password the length rules
            // already accepted, and a third party being unreachable must not be the reason nobody
            // in the deployment can register or change a password. Broad, because a corpus that
            // answers something unexpected is the same situation as one that does not answer.
            logger.LogWarning(
                exception,
                "The breached-password check could not reach {ApiBaseAddress}, so the password was accepted without it.",
                settings.ApiBaseAddress);

            return errors;
        }

        return count >= settings.BreachThreshold ? [settings.Message] : errors;
    }
}
