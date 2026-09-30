using System.Text.Json;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Every expectation was captured from the shipped wire format, so a diff here is a diff a deployed
/// client would see.
/// </summary>
public class EndpointResponseSerialisationTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

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

        // The trailing nulls are shipped behaviour, so omitting them now would be a wire change.
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

    [Test]
    public async Task Validation_error_response_stays_camel_case()
    {
        var json = Serialise(new ValidationErrorResponse { Errors = ["Use at least 8 characters."] });

        await Assert.That(json).IsEqualTo(
            """
            {"errors":["Use at least 8 characters."]}
            """);
    }

    [Test]
    public async Task Step_up_challenge_response_does_not_claim_anything_is_required()
    {
        var json = Serialise(new StepUpChallengeResponse { Challenge = "No1CXq9", ExpiresIn = 300 });

        await Assert.That(json).IsEqualTo(
            """
            {"challenge":"No1CXq9","expires_in":300}
            """);
    }

    /// <summary>
    /// Sharing <see cref="TokenResponse"/> would put <c>refresh_token: null</c> here, and a client
    /// that stored what came back would blank the credential it needs to stay signed in.
    /// </summary>
    [Test]
    public async Task Step_up_response_carries_an_access_token_and_no_refresh_token()
    {
        var json = Serialise(new StepUpResponse { AccessToken = "at", ExpiresIn = 900 });

        await Assert.That(json).IsEqualTo(
            """
            {"access_token":"at","expires_in":900,"token_type":"Bearer","recovery_codes_running_low":null}
            """);

        await Assert.That(json).DoesNotContain("refresh_token");
    }

    [Test]
    public async Task Step_up_response_reports_running_low_the_same_way_a_sign_in_does()
    {
        var json = Serialise(new StepUpResponse { AccessToken = "at", ExpiresIn = 900, RecoveryCodesRunningLow = true });

        await Assert.That(json).Contains("\"recovery_codes_running_low\":true");
    }

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
