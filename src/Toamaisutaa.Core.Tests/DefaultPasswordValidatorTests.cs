using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class DefaultPasswordValidatorTests
{
    private static DefaultPasswordValidator Validator() =>
        new(Options.Create(new ToamaisutaaLocalLoginOptions()));

    [Test]
    public async Task AcceptsAPasswordAtTheMinimum()
    {
        await Assert.That(Validator().Validate(new string('a', 8))).IsEmpty();
    }

    [Test]
    public async Task RejectsOneCharacterShort()
    {
        await Assert.That(Validator().Validate(new string('a', 7))).IsNotEmpty();
    }

    [Test]
    public async Task RejectsAnEmptyPassword()
    {
        await Assert.That(Validator().Validate(string.Empty)).IsNotEmpty();
    }

    [Test]
    public async Task AcceptsAPasswordAtTheMaximum()
    {
        await Assert.That(Validator().Validate(new string('a', 128))).IsEmpty();
    }

    // Not a strength rule: HMAC folds anything past its block size to a fixed width, so the extra
    // characters buy nothing while an unbounded field on an anonymous endpoint costs real work.
    [Test]
    public async Task RejectsOneCharacterOverTheMaximum()
    {
        await Assert.That(Validator().Validate(new string('a', 129))).IsNotEmpty();
    }

    [Test]
    public async Task ImposesNoCompositionRules()
    {
        await Assert.That(Validator().Validate("aaaaaaaaaaaaaaaa")).IsEmpty();
        await Assert.That(Validator().Validate("correct horse battery staple")).IsEmpty();
    }
}
