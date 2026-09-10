using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

public class HibpPasswordValidatorTests
{
    private const string Breached = "correct horse battery staple";

    private static HibpPasswordValidator Validator(
        IBreachedPasswordIndex index,
        out FakeLogger<HibpPasswordValidator> logger,
        IPasswordValidator? inner = null,
        Action<ToamaisutaaHibpOptions>? configure = null)
    {
        var options = new ToamaisutaaHibpOptions();
        configure?.Invoke(options);

        logger = new FakeLogger<HibpPasswordValidator>();

        return new HibpPasswordValidator(inner ?? new FakeInnerValidator(), index, Options.Create(options), logger);
    }

    [Test]
    public async Task RefusesAPasswordTheCorpusHasSeen()
    {
        var errors = await Validator(new FakeBreachedPasswordIndex(count: 4), out _).ValidateAsync(Breached);

        await Assert.That(errors).HasSingleItem();
        await Assert.That(errors[0]).Contains("data breach");
    }

    [Test]
    public async Task AcceptsAPasswordTheCorpusHasNotSeen()
    {
        await Assert.That(await Validator(new FakeBreachedPasswordIndex(count: 0), out _).ValidateAsync(Breached)).IsEmpty();
    }

    [Test]
    public async Task SaysWhatTheOptionsSayToSay()
    {
        var errors = await Validator(
            new FakeBreachedPasswordIndex(count: 1),
            out _,
            configure: options => options.Message = "Pick another one.").ValidateAsync(Breached);

        await Assert.That(errors).IsEquivalentTo(new[] { "Pick another one." });
    }

    // The threshold is a count of appearances, so it is the boundary that matters: at it, refused;
    // one below, allowed.
    [Test]
    public async Task RefusesAtTheThreshold()
    {
        var errors = await Validator(
            new FakeBreachedPasswordIndex(count: 10),
            out _,
            configure: options => options.BreachThreshold = 10).ValidateAsync(Breached);

        await Assert.That(errors).IsNotEmpty();
    }

    [Test]
    public async Task AcceptsOneAppearanceBelowTheThreshold()
    {
        var errors = await Validator(
            new FakeBreachedPasswordIndex(count: 9),
            out _,
            configure: options => options.BreachThreshold = 10).ValidateAsync(Breached);

        await Assert.That(errors).IsEmpty();
    }

    [Test]
    public async Task KeepsTheWrappedValidatorsErrors()
    {
        var inner = new FakeInnerValidator("Use at least 8 characters.");

        var errors = await Validator(new FakeBreachedPasswordIndex(count: 0), out _, inner).ValidateAsync("short");

        await Assert.That(errors).IsEquivalentTo(new[] { "Use at least 8 characters." });
    }

    // Nothing is learned by asking about a password that is already refused, and asking would spend
    // a request on every short password typed into an anonymous endpoint.
    [Test]
    public async Task DoesNotAskAboutAPasswordTheWrappedValidatorAlreadyRefused()
    {
        var index = new FakeBreachedPasswordIndex(count: 5000);

        await Validator(index, out _, new FakeInnerValidator("Use at least 8 characters.")).ValidateAsync("short");

        await Assert.That(index.Asked).IsEmpty();
    }

    [Test]
    public async Task AcceptsThePasswordWhenTheServiceIsUnreachable()
    {
        var index = new FakeBreachedPasswordIndex(count: 0, throws: new HttpRequestException("no route to host"));

        await Assert.That(await Validator(index, out _).ValidateAsync(Breached)).IsEmpty();
    }

    [Test]
    public async Task WarnsWhenItAcceptsAPasswordWithoutChecking()
    {
        var index = new FakeBreachedPasswordIndex(count: 0, throws: new HttpRequestException("no route to host"));

        await Validator(index, out var logger).ValidateAsync(Breached);

        await Assert.That(logger.Entries).HasSingleItem();
        await Assert.That(logger.Entries[0].Level).IsEqualTo(LogLevel.Warning);
        await Assert.That(logger.Entries[0].Message).Contains("api.pwnedpasswords.com");
    }

    // The password is the one thing that must never reach a log. A warning about a lookup that
    // failed is written while something has gone wrong, which is exactly when somebody is tempted
    // to put the input in it.
    [Test]
    public async Task NeverPutsThePasswordInTheWarning()
    {
        var index = new FakeBreachedPasswordIndex(count: 0, throws: new HttpRequestException("no route to host"));

        await Validator(index, out var logger).ValidateAsync(Breached);

        await Assert.That(logger.Entries.Any(entry => entry.Message.Contains(Breached, StringComparison.OrdinalIgnoreCase))).IsFalse();
    }

    // A corpus answering something unexpected is the same situation as one not answering: the
    // password already passed the length rules, and nobody should be locked out of a password
    // change by it.
    [Test]
    public async Task AcceptsThePasswordWhenTheServiceAnswersSomethingUnexpected()
    {
        var index = new FakeBreachedPasswordIndex(count: 0, throws: new InvalidOperationException("that was not a range response"));

        await Assert.That(await Validator(index, out _).ValidateAsync(Breached)).IsEmpty();
    }

    // Failing open covers the service, not the caller. A cancelled request is the caller giving up,
    // and swallowing it would report a decision nobody waited for.
    [Test]
    public async Task LetsTheCallersCancellationThrough()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        var index = new FakeBreachedPasswordIndex(count: 0, throws: new OperationCanceledException(cancelled.Token));

        await Assert.That(async () => await Validator(index, out _).ValidateAsync(Breached, cancelled.Token))
            .Throws<OperationCanceledException>();
    }

    // Nothing in the package calls it, but the interface still carries it, so it has to agree with
    // the async answer rather than quietly skipping the check.
    [Test]
    public async Task TheSynchronousPathReachesTheSameAnswer()
    {
        await Assert.That(Validator(new FakeBreachedPasswordIndex(count: 4), out _).Validate(Breached)).IsNotEmpty();
        await Assert.That(Validator(new FakeBreachedPasswordIndex(count: 0), out _).Validate(Breached)).IsEmpty();
    }
}
