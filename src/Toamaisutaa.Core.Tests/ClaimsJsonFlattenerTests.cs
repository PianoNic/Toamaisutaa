namespace Toamaisutaa.Core.Tests;

public class ClaimsJsonFlattenerTests
{
    [Test]
    public async Task ReadsStringProperties()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"sub":"abc-123","email":"nic@example.com"}""");

        await Assert.That(claims).Contains(("sub", "abc-123"));
        await Assert.That(claims).Contains(("email", "nic@example.com"));
    }

    [Test]
    public async Task ReadsNumbersAndBooleans()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"updated_at":1699999999,"email_verified":true,"locked":false}""");

        await Assert.That(claims).Contains(("updated_at", "1699999999"));
        await Assert.That(claims).Contains(("email_verified", "True"));
        await Assert.That(claims).Contains(("locked", "False"));
    }

    // The reason this method exists: a role check matches a single claim value, so a groups array
    // has to arrive as one claim per group or membership can never be satisfied.
    [Test]
    public async Task ArraysBecomeOneClaimPerEntry()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"groups":["admin","ops","readers"]}""");

        await Assert.That(claims.Count(claim => claim.Type == "groups")).IsEqualTo(3);
        await Assert.That(claims).Contains(("groups", "admin"));
        await Assert.That(claims).Contains(("groups", "ops"));
        await Assert.That(claims).Contains(("groups", "readers"));
    }

    [Test]
    public async Task MixedArrayEntriesAreFlattenedIndividually()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"levels":[1,true,"three"]}""");

        await Assert.That(claims).Contains(("levels", "1"));
        await Assert.That(claims).Contains(("levels", "True"));
        await Assert.That(claims).Contains(("levels", "three"));
    }

    // A claim value is a string. Inventing a serialisation for an object would be a format nobody
    // else agrees on, so these are dropped rather than guessed at.
    [Test]
    public async Task NestedObjectsAreSkipped()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"sub":"abc","address":{"country":"CH"}}""");

        await Assert.That(claims).Contains(("sub", "abc"));
        await Assert.That(claims.Any(claim => claim.Type == "address")).IsFalse();
    }

    [Test]
    public async Task ObjectsAndArraysInsideArraysAreSkipped()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"roles":["admin",{"name":"ops"},["nested"]]}""");

        await Assert.That(claims.Count(claim => claim.Type == "roles")).IsEqualTo(1);
        await Assert.That(claims).Contains(("roles", "admin"));
    }

    [Test]
    public async Task EmptyStringsAndNullsAreDropped()
    {
        var claims = ClaimsJsonFlattener.Parse("""{"sub":"abc","nickname":"","middle_name":null}""");

        await Assert.That(claims.Count).IsEqualTo(1);
        await Assert.That(claims).Contains(("sub", "abc"));
    }

    [Test]
    [Arguments("[]")]
    [Arguments("\"a string\"")]
    [Arguments("42")]
    public async Task NonObjectRootsYieldNothing(string json)
    {
        await Assert.That(ClaimsJsonFlattener.Parse(json)).IsEmpty();
    }
}
