using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordValidation.Hibp;

internal sealed class HibpPasswordValidator(
    IPasswordValidator inner,
    IBreachedPasswordIndex index,
    IOptions<ToamaisutaaHibpOptions> options,
    ILogger<HibpPasswordValidator> logger) : IPasswordValidator
{
    /// <summary>Blocks on the lookup; the package itself only calls <see cref="ValidateAsync"/>.</summary>
    public IReadOnlyList<string> Validate(string password) =>
        ValidateAsync(password).AsTask().GetAwaiter().GetResult();

    public async ValueTask<IReadOnlyList<string>> ValidateAsync(string password, CancellationToken cancellationToken = default)
    {
        var errors = await inner.ValidateAsync(password, cancellationToken);

        // Asking about an already-refused password would spend a request on every short password
        // typed into an anonymous endpoint.
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
            // Fails open deliberately, so an unreachable third party cannot block every registration
            // and password change. Broad, because an unexpected answer is the same as no answer.
            logger.LogWarning(
                exception,
                "The breached-password check could not reach {ApiBaseAddress}, so the password was accepted without it.",
                settings.ApiBaseAddress);

            return errors;
        }

        return count >= settings.BreachThreshold ? [settings.Message] : errors;
    }
}
