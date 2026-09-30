namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// A record rather than a tuple because System.Text.Json writes a ValueTuple as an empty object in a
/// distributed cache.
/// </summary>
internal sealed record UserInfoClaim(string Type, string Value);
