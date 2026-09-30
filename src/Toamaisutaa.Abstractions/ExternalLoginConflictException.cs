namespace Toamaisutaa.Abstractions;

/// <summary>
/// The (provider, subject) pair already exists, so the loser of a concurrent first sign-in re-reads
/// and carries on. Stores translate their own unique-violation into it.
/// </summary>
public sealed class ExternalLoginConflictException : Exception
{
    public ExternalLoginConflictException(string providerKey, string subject, Exception? innerException = null)
        : base($"An external login already exists for provider '{providerKey}'.", innerException)
    {
        ProviderKey = providerKey;
        Subject = subject;
    }

    public string ProviderKey { get; }

    /// <summary>Not put in the message: it identifies a person and messages end up in logs.</summary>
    public string Subject { get; }
}
