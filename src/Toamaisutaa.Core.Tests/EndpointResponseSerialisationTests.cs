using System.Text.Json;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The wire contract of the endpoints, asserted as literal JSON.
/// </summary>
/// <remarks>
/// <para>
/// These shapes were anonymous objects until they had types, which meant the RFC 6749 field names
/// were C# identifiers in an endpoint file and a rename would have changed the API without
/// producing a single failing test. Every expectation below was captured from the running sample on
/// 0.3.0 before the types existed, so a diff here is a diff a deployed client would see.
/// </para>
/// <para>
/// Serialised through <see cref="JsonSerializerDefaults.Web"/> - the same defaults minimal APIs use
/// - so the camelCase naming policy is applied exactly as it is in production. That is the point:
/// the assertions prove the pinned names survive a policy that would otherwise rewrite them.
/// </para>
/// </remarks>
public class EndpointResponseSerialisationTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// An application is free to configure its own naming policy, and several do. A response that
    /// took its field names from a policy would change shape underneath the consumer who did.
    /// </summary>
    private static readonly JsonSerializerOptions SnakeCase = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private static string Serialise<T>(T value, JsonSerializerOptions? options = null) =>
        JsonSerializer.Serialize(value, options ?? Web);

    [Test]
    public async Task Token_response_is_the_RFC_6749_shape()
    {
        var json = Serialise(new TokenResponse
        {
            AccessToken = "at",
            RefreshToken = "rt",
            ExpiresIn = 900,
        });

        // The three trailing nulls are shipped behaviour, not an oversight: 0.2.0 and 0.3.0 both
        // emit them on every sign-in, so omitting them now would be a wire change.
        await Assert.That(json).IsEqualTo(
            """
            {"access_token":"at","refresh_token":"rt","expires_in":900,"token_type":"Bearer","recovery_codes_running_low":null,"device_token":null,"device_expires_in":null}
            """);
    }

    [Test]
    public async Task Token_response_carries_the_device_fields_when_a_device_was_trusted()
    {
        var json = Serialise(new TokenResponse
        {
            AccessToken = "at",
            RefreshToken = "rt",
            ExpiresIn = 900,
            DeviceToken = "dt",
            DeviceExpiresIn = 2592000,
        });

        await Assert.That(json).IsEqualTo(
            """
            {"access_token":"at","refresh_token":"rt","expires_in":900,"token_type":"Bearer","recovery_codes_running_low":null,"device_token":"dt","device_expires_in":2592000}
            """);
    }

    /// <summary>
    /// True or absent, never false. A client written against 0.2.0 reads this as truthy rather than
    /// comparing it, so emitting <c>false</c> would be a change even though the meaning is the same.
    /// </summary>
    [Test]
    public async Task Recovery_codes_running_low_is_true_or_null_and_never_false()
    {
        var low = Serialise(new TokenResponse
        {
            AccessToken = "at",
            RefreshToken = "rt",
            ExpiresIn = 900,
            RecoveryCodesRunningLow = true,
        });

        await Assert.That(low).Contains("\"recovery_codes_running_low\":true");

        var notLow = Serialise(new TokenResponse { AccessToken = "at", RefreshToken = "rt", ExpiresIn = 900 });

        await Assert.That(notLow).Contains("\"recovery_codes_running_low\":null");
        await Assert.That(notLow).DoesNotContain("false");
    }

    [Test]
    public async Task Two_factor_challenge_response_is_the_documented_shape()
    {
        var json = Serialise(new TwoFactorChallengeResponse { Challenge = "No1CXq9", ExpiresIn = 300 });

        await Assert.That(json).IsEqualTo(
            """
            {"two_factor_required":true,"challenge":"No1CXq9","expires_in":300}
            """);
    }

    [Test]
    public async Task Error_response_is_the_RFC_6749_shape()
    {
        var json = Serialise(new ErrorResponse
        {
            Error = "invalid_grant",
            ErrorDescription = "The credentials are not valid.",
        });

        await Assert.That(json).IsEqualTo(
            """
            {"error":"invalid_grant","error_description":"The credentials are not valid."}
            """);
    }

    /// <summary>
    /// The one response body here that is camelCase, because no standard names it. Asserted so the
    /// asymmetry is a decision the codebase holds rather than an accident nobody noticed.
    /// </summary>
    [Test]
    public async Task Validation_error_response_stays_camel_case()
    {
        var json = Serialise(new ValidationErrorResponse { Errors = ["Use at least 8 characters."] });

        await Assert.That(json).IsEqualTo(
            """
            {"errors":["Use at least 8 characters."]}
            """);
    }

    /// <summary>
    /// The failure this whole file exists to catch. An application that sets its own naming policy
    /// would, without the pinned names, silently reshape a standard token response.
    /// </summary>
    [Test]
    public async Task Field_names_survive_an_application_naming_policy()
    {
        var token = Serialise(
            new TokenResponse { AccessToken = "at", RefreshToken = "rt", ExpiresIn = 900 },
            SnakeCase);

        await Assert.That(token).Contains("\"access_token\":\"at\"");
        await Assert.That(token).Contains("\"token_type\":\"Bearer\"");

        var validation = Serialise(new ValidationErrorResponse { Errors = ["nope"] }, SnakeCase);

        await Assert.That(validation).IsEqualTo(
            """
            {"errors":["nope"]}
            """);
    }
}
