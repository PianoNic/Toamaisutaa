using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Raw JSON rather than the package's own records, because deserialising through
/// <c>TokenResponse</c> would make every assertion agree with whatever that type currently says.</summary>
internal static class Http
{
    public static async Task<JsonElement> Json(this HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    public static string? String(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static bool? Bool(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : null;

    /// <summary>Empty when the property is missing, so a test asserting emptiness checks the name is
    /// there as well.</summary>
    public static IReadOnlyList<string> Strings(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? [.. value.EnumerateArray().Select(item => item.GetString()!)]
            : [];

    /// <summary>Not <see cref="Strings"/>, because a token carrying one method serialises <c>amr</c> as
    /// a bare string.</summary>
    public static IReadOnlyList<string> Amr(this JsonElement claims)
    {
        if (!claims.TryGetProperty("amr", out var amr))
            return [];

        return amr.ValueKind == JsonValueKind.Array
            ? [.. amr.EnumerateArray().Select(value => value.GetString()!)]
            : [amr.GetString()!];
    }

    public static bool Has(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is not JsonValueKind.Null;

    public static IReadOnlyList<string> Names(this JsonElement element) =>
        [.. element.EnumerateObject().Select(property => property.Name)];

    public static Task<HttpResponseMessage> PostJson(this HttpClient client, string path, object body) =>
        client.PostAsJsonAsync(path, body);

    public static Task<HttpResponseMessage> PostJson(this HttpClient client, string path, object body, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.SendAsync(request);
    }

    public static Task<HttpResponseMessage> PostEmpty(this HttpClient client, string path, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.SendAsync(request);
    }

    public static Task<HttpResponseMessage> Delete(this HttpClient client, string path, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.SendAsync(request);
    }

    public static Task<HttpResponseMessage> Delete(this HttpClient client, string path, object body, string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, path) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.SendAsync(request);
    }

    public static Task<HttpResponseMessage> Get(this HttpClient client, string path, string? accessToken = null, string? deviceToken = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);

        if (accessToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        if (deviceToken is not null)
            request.Headers.Add("X-Toamaisutaa-Device", deviceToken);

        return client.SendAsync(request);
    }
}

/// <summary>RFC 6238 written out independently, because a generator borrowed from the code under test
/// agrees with it even when both are wrong.</summary>
internal static class Totp
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Code(string base32Secret, DateTimeOffset at)
    {
        var secret = DecodeBase32(base32Secret);
        var step = at.ToUnixTimeSeconds() / 30;

        var counter = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counter);

        var hash = HMACSHA1.HashData(secret, counter);
        var offset = hash[^1] & 0x0F;

        var binary =
            ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            | (hash[offset + 3] & 0xFF);

        return (binary % 1_000_000).ToString("D6");
    }

    /// <summary>The right code with its first digit moved on, which no drift step will also produce
    /// outside a one-in-a-million coincidence.</summary>
    public static string WrongCode(string base32Secret, DateTimeOffset at)
    {
        var code = Code(base32Secret, at);
        return (char)('0' + ((code[0] - '0' + 1) % 10)) + code[1..];
    }

    private static byte[] DecodeBase32(string value)
    {
        var trimmed = value.TrimEnd('=').ToUpperInvariant();
        var bits = 0;
        var accumulator = 0;
        var bytes = new List<byte>();

        foreach (var character in trimmed)
        {
            accumulator = (accumulator << 5) | Base32Alphabet.IndexOf(character);
            bits += 5;

            if (bits < 8)
                continue;

            bits -= 8;
            bytes.Add((byte)((accumulator >> bits) & 0xFF));
        }

        return [.. bytes];
    }
}
