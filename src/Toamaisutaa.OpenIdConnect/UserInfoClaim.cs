namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// One claim read from userinfo, in the shape it is cached in.
/// </summary>
/// <remarks>
/// The flattener hands back <c>(string, string)</c> tuples, which is the right shape to read and the
/// wrong one to store: a cached value can be serialised into a consumer's distributed cache, and
/// System.Text.Json writes a ValueTuple's fields as an empty object.
/// </remarks>
internal sealed record UserInfoClaim(string Type, string Value);
