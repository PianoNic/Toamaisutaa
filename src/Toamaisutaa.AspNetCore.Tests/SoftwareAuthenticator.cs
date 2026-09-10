using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A WebAuthn authenticator in software: an EC P-256 key, a credential id, and the two structures a
/// real one produces.
/// </summary>
/// <remarks>
/// <para>
/// Written out here rather than driven through anything in the package, for the reason
/// <c>Totp</c> next door is: a generator borrowed from the code under test agrees with that code
/// even when both are wrong. Everything below is built from the specification - the CBOR attestation
/// object, the flags byte, the concatenation that gets signed - so a change to how the package
/// verifies an assertion has something independent to disagree with.
/// </para>
/// <para>
/// It is also the only way to test any of this without a browser and a physical key, which is
/// exactly the gap that let three previous bugs reach the wire.
/// </para>
/// </remarks>
internal sealed class SoftwareAuthenticator : IDisposable
{
    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;
    private const byte BackupEligible = 0x08;
    private const byte BackedUp = 0x10;
    private const byte AttestedCredentialData = 0x40;

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>All zero, which is what a platform authenticator that declines to identify its model
    /// reports - and the common case.</summary>
    private readonly byte[] _aaGuid = new byte[16];

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>Taken from the registration options, and handed back on every assertion - which is
    /// the only thing that says who is signing in when no identifier was typed.</summary>
    public byte[] UserHandle { get; private set; } = [];

    /// <summary>What the authenticator claims it has signed so far. A real one only ever increases
    /// it; setting it by hand is how the clone-detection test misbehaves on purpose.</summary>
    public uint SignCount { get; set; }

    /// <summary>Whether this authenticator reports the credential as synced to the user's provider.
    /// Off by default, matching a key that is bound to the hardware.</summary>
    public bool Synced { get; set; }

    /// <summary>
    /// What <c>navigator.credentials.create()</c> would return, as the endpoint takes it.
    /// </summary>
    /// <param name="begin">The body of <c>/register/begin</c>, opaque challenge and options both.</param>
    /// <param name="origin">The page the ceremony is happening on.</param>
    /// <param name="userVerified">False to act as an authenticator that only checked for a touch.</param>
    public object Create(JsonElement begin, string origin, bool userVerified = true)
    {
        var options = begin.GetProperty("options");
        var challenge = options.GetProperty("challenge").GetString()!;
        var rpId = options.GetProperty("rp").GetProperty("id").GetString()!;

        UserHandle = Decode(options.GetProperty("user").GetProperty("id").GetString()!);

        var clientData = ClientData("webauthn.create", challenge, origin);
        var authenticatorData = AuthenticatorData(rpId, userVerified, withCredential: true);

        return new
        {
            challenge = begin.GetProperty("challenge").GetString(),
            id = Encode(CredentialId),
            attestationObject = Encode(AttestationObject(authenticatorData)),
            clientDataJson = Encode(clientData),
            transports = new[] { "internal" },
        };
    }

    /// <summary>What <c>navigator.credentials.get()</c> would return, signature and all.</summary>
    /// <param name="begin">The body of <c>/assertion/begin</c>, opaque challenge and options both.</param>
    /// <param name="origin">The page the ceremony is happening on.</param>
    /// <param name="userVerified">False to act as an authenticator that only checked for a touch.</param>
    public object Get(JsonElement begin, string origin, bool userVerified = true)
    {
        var options = begin.GetProperty("options");
        var challenge = options.GetProperty("challenge").GetString()!;
        var rpId = options.GetProperty("rpId").GetString()!;

        SignCount++;

        var clientData = ClientData("webauthn.get", challenge, origin);
        var authenticatorData = AuthenticatorData(rpId, userVerified, withCredential: false);

        // Exactly what WebAuthn says is signed: the authenticator data, then the hash of the client
        // data. Nothing else, and in that order.
        var signed = new byte[authenticatorData.Length + 32];
        authenticatorData.CopyTo(signed, 0);
        SHA256.HashData(clientData).CopyTo(signed, authenticatorData.Length);

        return new
        {
            challenge = begin.GetProperty("challenge").GetString(),
            id = Encode(CredentialId),
            authenticatorData = Encode(authenticatorData),
            clientDataJson = Encode(clientData),
            signature = Encode(_key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)),
            userHandle = Encode(UserHandle),
        };
    }

    public void Dispose() => _key.Dispose();

    public static string Encode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string value)
    {
        var normalised = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(normalised.PadRight(normalised.Length + ((4 - (normalised.Length % 4)) % 4), '='));
    }

    private static byte[] ClientData(string type, string challenge, string origin) =>
        Encoding.UTF8.GetBytes(
            $$"""{"type":"{{type}}","challenge":"{{challenge}}","origin":"{{origin}}","crossOrigin":false}""");

    /// <summary>
    /// The relying party hash, the flags, the counter, and - at registration - the credential
    /// itself. Laid out by hand, because getting this layout wrong is precisely the failure the
    /// package's verification exists to catch.
    /// </summary>
    private byte[] AuthenticatorData(string rpId, bool userVerified, bool withCredential)
    {
        var data = new List<byte>(37);

        data.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));

        var flags = UserPresent;

        if (userVerified)
            flags |= UserVerified;

        // Backed up is only meaningful for a credential that is eligible for it, and an
        // authenticator reporting the second without the first is refused - correctly.
        if (Synced)
            flags |= BackupEligible | BackedUp;

        if (withCredential)
            flags |= AttestedCredentialData;

        data.Add(flags);

        var counter = BitConverter.GetBytes(SignCount);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counter);

        data.AddRange(counter);

        if (!withCredential)
            return [.. data];

        data.AddRange(_aaGuid);
        data.AddRange([(byte)(CredentialId.Length >> 8), (byte)(CredentialId.Length & 0xFF)]);
        data.AddRange(CredentialId);
        data.AddRange(CosePublicKey());

        return [.. data];
    }

    /// <summary>The COSE_Key of RFC 8152, which is how WebAuthn carries a public key.</summary>
    private byte[] CosePublicKey()
    {
        var parameters = _key.ExportParameters(includePrivateParameters: false);
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt32(-7);
        writer.WriteInt32(-1);
        writer.WriteInt32(1);
        writer.WriteInt32(-2);
        writer.WriteByteString(parameters.Q.X!);
        writer.WriteInt32(-3);
        writer.WriteByteString(parameters.Q.Y!);
        writer.WriteEndMap();

        return writer.Encode();
    }

    /// <summary>Attestation format <c>none</c>: no statement, no certificate, nothing to verify
    /// beyond the authenticator data itself. What every platform authenticator produces by default,
    /// and what this package asks for.</summary>
    private static byte[] AttestationObject(byte[] authenticatorData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authenticatorData);
        writer.WriteEndMap();

        return writer.Encode();
    }
}
