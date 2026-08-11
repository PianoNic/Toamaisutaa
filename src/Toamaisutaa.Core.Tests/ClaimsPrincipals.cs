using System.Security.Claims;

namespace Toamaisutaa.Core.Tests;

internal static class ClaimsPrincipals
{
    /// <summary>An authenticated principal carrying exactly the claims given, with raw JWT claim
    /// types, which is what the bearer layer produces.</summary>
    internal static ClaimsPrincipal With(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), "Toamaisutaa.Tests"));
}
