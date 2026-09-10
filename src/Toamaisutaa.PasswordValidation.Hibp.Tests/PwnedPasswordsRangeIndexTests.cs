using System.Net;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

/// <summary>
/// The wire format, and the k-anonymity promise that rests on it.
/// </summary>
/// <remarks>
/// The hashes below were computed outside this solution, not taken from the code under test, for
/// the same reason <c>TotpProviderTests</c> asserts published vectors: a fixture borrowed from the
/// implementation agrees with it even when both are wrong. SHA-1 of "password" is
/// 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, which is the example the Pwned Passwords range API is
/// documented with.
/// </remarks>
public class PwnedPasswordsRangeIndexTests
{
    private const string Password = "password";
    private const string Prefix = "5BAA6";
    private const string Suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static PwnedPasswordsRangeIndex Index(HttpMessageHandler handler, Action<ToamaisutaaHibpOptions>? configure = null)
    {
        var options = new ToamaisutaaHibpOptions();
        configure?.Invoke(options);

        return new PwnedPasswordsRangeIndex(new StubHttpClientFactory(handler), Options.Create(options));
    }

    private static string Range(params string[] lines) => string.Join("\r\n", lines);

    [Test]
    public async Task ReadsTheCountForItsOwnSuffix()
    {
        var handler = RecordingHandler.Answering(Range(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1",
            $"{Suffix}:12345",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"));

        await Assert.That(await Index(handler).CountAsync(Password)).IsEqualTo(12345);
    }

    [Test]
    public async Task AnswersZeroWhenTheSuffixIsNotInTheRange()
    {
        var handler = RecordingHandler.Answering(Range(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"));

        await Assert.That(await Index(handler).CountAsync(Password)).IsEqualTo(0);
    }

    // The API answers in upper case, but nothing in the protocol promises it will keep doing so,
    // and a case mismatch would silently mean "not breached" for every password.
    [Test]
    public async Task MatchesTheSuffixWhateverCaseItComesBackIn()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix.ToLowerInvariant()}:7"));

        await Assert.That(await Index(handler).CountAsync(Password)).IsEqualTo(7);
    }

    // The whole privacy claim in one assertion: five characters of the hash, and nothing else about
    // the password, anywhere in the request.
    //
    // On a different vector from the rest of the class, and that is the point of it being here:
    // "password" is a substring of the host name, so asserting the request does not contain it
    // passed while saying nothing. SHA-1 of "correct horse battery staple" is
    // ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42.
    [Test]
    public async Task SendsTheFirstFiveCharactersOfTheHashAndNothingElse()
    {
        const string password = "correct horse battery staple";
        const string prefix = "ABF7A";
        const string suffix = "AD6438836DBE526AA231ABDE2D0EEF74D42";

        var handler = RecordingHandler.Answering(Range($"{suffix}:1"));

        await Index(handler).CountAsync(password);

        var request = handler.Requests.Single();
        var sent = request.RequestUri!.ToString();

        await Assert.That(sent).IsEqualTo($"https://api.pwnedpasswords.com/range/{prefix}");
        await Assert.That(sent).DoesNotContain(suffix, StringComparison.OrdinalIgnoreCase);
        await Assert.That(sent).DoesNotContain(password, StringComparison.OrdinalIgnoreCase);
        await Assert.That(sent).DoesNotContain("horse", StringComparison.OrdinalIgnoreCase);
        await Assert.That(request.Content).IsNull();
    }

    // Padding entries carry a count of zero, so a threshold of one or more discards them without the
    // parser knowing they exist. This asserts they cannot be read as a hit.
    [Test]
    public async Task ReadsAPaddingEntryAsNoAppearances()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:0"));

        await Assert.That(await Index(handler).CountAsync(Password)).IsEqualTo(0);
    }

    [Test]
    public async Task AsksForAPaddedResponse()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:1"));

        await Index(handler).CountAsync(Password);

        await Assert.That(handler.Requests.Single().Headers.TryGetValues("Add-Padding", out var padding)).IsTrue();
        await Assert.That(padding!.Single()).IsEqualTo("true");
    }

    // The range API answers 400 to a request with no user agent, which would fail every lookup and
    // look exactly like the service being down.
    [Test]
    public async Task SendsTheConfiguredUserAgent()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:1"));

        await Index(handler, options => options.UserAgent = "gatekeeper/1.0").CountAsync(Password);

        await Assert.That(handler.Requests.Single().Headers.UserAgent.ToString()).IsEqualTo("gatekeeper/1.0");
    }

    [Test]
    public async Task GoesWhereTheBaseAddressPoints()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:1"));

        await Index(handler, options => options.ApiBaseAddress = "https://mirror.internal/pwned/").CountAsync(Password);

        await Assert.That(handler.Requests.Single().RequestUri!.ToString())
            .IsEqualTo($"https://mirror.internal/pwned/range/{Prefix}");
    }

    // Resolving "range/{prefix}" against a base address replaces its last segment, so the mirror
    // written down without a trailing slash was asked for a path nobody hosts. The 404 fails open,
    // which is breach checking that is off while looking on.
    [Test]
    [Arguments("https://mirror.internal/pwned", "https://mirror.internal/pwned/range/")]
    [Arguments("https://mirror.internal/hibp/v1", "https://mirror.internal/hibp/v1/range/")]
    [Arguments("https://mirror.internal", "https://mirror.internal/range/")]
    public async Task KeepsEverySegmentOfABaseAddressThatDoesNotEndInASlash(string address, string expected)
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:1"));

        await Index(handler, options => options.ApiBaseAddress = address).CountAsync(Password);

        await Assert.That(handler.Requests.Single().RequestUri!.ToString()).IsEqualTo(expected + Prefix);
    }

    [Test]
    public async Task ResolvesTheNamedClientSoAHandlerCanBePutInFrontOfIt()
    {
        var handler = RecordingHandler.Answering(Range($"{Suffix}:1"));
        var factory = new StubHttpClientFactory(handler);

        await new PwnedPasswordsRangeIndex(factory, Options.Create(new ToamaisutaaHibpOptions())).CountAsync(Password);

        await Assert.That(factory.Named).IsEquivalentTo(new[] { ToamaisutaaHibpDefaults.HttpClientName });
    }

    [Test]
    public async Task ThrowsWhenTheServiceAnswersAnError()
    {
        var handler = new RecordingHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));

        await Assert.That(async () => await Index(handler).CountAsync(Password)).Throws<HttpRequestException>();
    }

    [Test]
    public async Task ThrowsWhenTheServiceIsUnreachable()
    {
        var handler = RecordingHandler.Failing(new HttpRequestException("no route to host"));

        await Assert.That(async () => await Index(handler).CountAsync(Password)).Throws<HttpRequestException>();
    }

    // The timeout is the options one, per request, so changing it in configuration takes effect
    // without the named client being rebuilt. Timed rather than merely awaited: falling back to
    // HttpClient's own timeout would also throw here, a hundred seconds later, with a registration
    // held open for all of them - and an awaited assertion cannot tell the two apart.
    [Test]
    public async Task GivesUpAfterTheConfiguredTimeoutRatherThanTheClients()
    {
        var handler = RecordingHandler.Hanging();

        var lookup = Index(handler, options => options.Timeout = TimeSpan.FromMilliseconds(50)).CountAsync(Password).AsTask();
        var first = await Task.WhenAny(lookup, Task.Delay(TimeSpan.FromSeconds(2)));

        await Assert.That(ReferenceEquals(first, lookup)).IsTrue();
        await Assert.That(async () => await lookup).Throws<OperationCanceledException>();
    }
}
