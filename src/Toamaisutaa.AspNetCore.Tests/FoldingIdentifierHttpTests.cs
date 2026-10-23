using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Upper-casing turns the long s (U+017F) into S, so "ſam@example.com" and "sam@example.com" are two
/// mailboxes with one normalised form. Accepting the first let it hold the second's identifier.
/// </summary>
public class FoldingIdentifierHttpTests
{
    [Test]
    public async Task An_address_that_folds_into_another_is_refused()
    {
        await using var app = await TestApp.StartAsync();

        var folded = await app.Client.PostJson("/auth/register", new { userName = "squatter", email = "ſam@example.com", password = Account.DefaultPassword });

        await Assert.That(folded.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task A_user_name_that_folds_into_another_is_refused()
    {
        await using var app = await TestApp.StartAsync();

        var folded = await app.Client.PostJson("/auth/register", new { userName = "ſam", email = "squatter@example.com", password = Account.DefaultPassword });

        await Assert.That(folded.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    /// <summary>Only letters that turn into others are refused; accented names and addresses round-trip.</summary>
    [Test]
    public async Task Accented_names_and_addresses_still_register()
    {
        await using var app = await TestApp.StartAsync();

        var accented = await app.Client.PostJson("/auth/register", new { userName = "josé", email = "josé@example.com", password = Account.DefaultPassword });

        await Assert.That(accented.StatusCode).IsEqualTo(HttpStatusCode.Created);
    }
}
