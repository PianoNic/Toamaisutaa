namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>
/// The <c>PasswordValidation:Hibp</c> configuration section. The defaults point at the public
/// Pwned Passwords range API and refuse a password that has appeared in it even once.
/// </summary>
public sealed class ToamaisutaaHibpOptions
{
    /// <summary>How many appearances in the corpus refuse a password.</summary>
    public int BreachThreshold { get; set; } = 1;

    /// <summary>
    /// Where the range API lives. Point it at a mirror of the downloadable corpus to keep the third
    /// party out of the path entirely.
    /// </summary>
    public string ApiBaseAddress { get; set; } = "https://api.pwnedpasswords.com/";

    /// <summary>
    /// How long to wait before giving up and letting the password through. Short because it sits in
    /// front of every registration and password change.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Sent as <c>User-Agent</c>. The range API refuses requests without one, and its
    /// operator asks that it name the calling application rather than a library.</summary>
    public string UserAgent { get; set; } = "Toamaisutaa";

    /// <summary>What the person choosing the password is told.</summary>
    public string Message { get; set; } = "That password has appeared in a known data breach. Choose a different one.";
}
