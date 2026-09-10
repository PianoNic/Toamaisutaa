namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>
/// Everything read from the <c>PasswordValidation:Hibp</c> configuration section. Nothing here has
/// to be set: the defaults point at the public Pwned Passwords range API and refuse a password that
/// has appeared in it even once.
/// </summary>
public sealed class ToamaisutaaHibpOptions
{
    /// <summary>
    /// How many appearances in the corpus refuse a password. The default refuses anything the
    /// corpus has ever seen; raise it if the long tail of single-appearance entries is turning away
    /// passwords you would rather allow.
    /// </summary>
    public int BreachThreshold { get; set; } = 1;

    /// <summary>
    /// Where the range API lives. Worth overriding for a mirror of the downloadable corpus on your
    /// own network, which is the only way to run this with no third party in the path at all.
    /// </summary>
    public string ApiBaseAddress { get; set; } = "https://api.pwnedpasswords.com/";

    /// <summary>
    /// How long to wait before giving up and letting the password through. Short on purpose: this
    /// sits in front of every registration and every password change, and a slow third party must
    /// not become a slow sign-up page.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Sent as <c>User-Agent</c>. The range API refuses requests without one, and its
    /// operator asks that it name the calling application rather than a library.</summary>
    public string UserAgent { get; set; } = "Toamaisutaa";

    /// <summary>What the person choosing the password is told. Like every other message this
    /// package shows them, it says what to do rather than what went wrong.</summary>
    public string Message { get; set; } = "That password has appeared in a known data breach. Choose a different one.";
}
