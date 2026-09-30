using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Built from the WebAuthn specification rather than anything in the package, because a generator
/// borrowed from the code under test agrees with that code even when both are wrong.
/// </summary>
internal sealed class SoftwareAuthenticator : IDisposable
{
    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;
    private const byte BackupEligible = 0x08;
    private const byte BackedUp = 0x10;
    private const byte AttestedCredentialData = 0x40;

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private readonly byte[] _aaGuid = new byte[16];

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

    public byte[] UserHandle { get; private set; } = [];

    public uint SignCount { get; set; }

    public bool Synced { get; set; }

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

    public object Get(JsonElement begin, string origin, bool userVerified = true)
    {
        var options = begin.GetProperty("options");
        var challenge = options.GetProperty("challenge").GetString()!;
        var rpId = options.GetProperty("rpId").GetString()!;

        SignCount++;

        var clientData = ClientData("webauthn.get", challenge, origin);
        var authenticatorData = AuthenticatorData(rpId, userVerified, withCredential: false);

        // WebAuthn signs exactly the authenticator data followed by the client data hash, in that order.
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

    private byte[] AuthenticatorData(string rpId, bool userVerified, bool withCredential)
    {
        var data = new List<byte>(37);

        data.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));

        var flags = UserPresent;

        if (userVerified)
            flags |= UserVerified;

        // Backed up without backup eligible is refused, so the two flags are always set together.
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
