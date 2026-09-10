namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>Names this package uses when nothing else is configured.</summary>
/// <remarks>Public for <see cref="HttpClientName"/>: adding a retry handler or an outbound proxy to
/// the lookup means naming the client, and the alternative is a consumer copying a string
/// literal.</remarks>
public static class ToamaisutaaHibpDefaults
{
    /// <summary>Named <c>HttpClient</c> the range lookup resolves. Configure it to put a handler in
    /// front of the lookup without replacing the validator.</summary>
    public const string HttpClientName = "toamaisutaa-hibp";

    /// <summary>Configuration section <see cref="ToamaisutaaHibpOptions"/> binds from.</summary>
    public const string ConfigurationSection = "PasswordValidation:Hibp";
}
