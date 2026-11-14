using System.Text.Json;
using System.Text.Json.Serialization;

namespace DscSync.Core.Protocol;

/// <summary>X.509 metadata of a certificate living on a token.</summary>
public sealed class CertificateDto
{
    /// <summary>CKA_ID of the certificate / key pair on the physical token.</summary>
    public byte[] Id { get; set; } = Array.Empty<byte>();
    public string Label { get; set; } = "";
    public byte[] Der { get; set; } = Array.Empty<byte>();
    public string SubjectCommonName { get; set; } = "";
    public string Organization { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string IssuerCommonName { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public int KeySizeBits { get; set; }
    public byte[] Modulus { get; set; } = Array.Empty<byte>();
    public byte[] PublicExponent { get; set; } = Array.Empty<byte>();
    public bool HasPrivateKey { get; set; }
}

/// <summary>One token present in one PKCS#11 slot on the Local PC.</summary>
public sealed class TokenInfoDto
{
    public ulong SlotId { get; set; }
    public string Vendor { get; set; } = "";
    public string LibraryPath { get; set; } = "";
    public string Label { get; set; } = "";
    public string Model { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public int MinPinLength { get; set; } = 4;
    public int MaxPinLength { get; set; } = 32;
    public List<CertificateDto> Certificates { get; set; } = new();
}

/// <summary>Snapshot of every token on the Local PC. <see cref="Generation"/> changes on every insert / removal.</summary>
public sealed class TokenStateDto
{
    public long Generation { get; set; }
    public DateTime TimestampUtc { get; set; }
    public List<TokenInfoDto> Tokens { get; set; } = new();
}

public enum TokenEventKind { Snapshot = 0, TokenInserted = 1, TokenRemoved = 2, TokenChanged = 3 }

public sealed class TokenEventDto
{
    public TokenEventKind Kind { get; set; }
    public TokenStateDto State { get; set; } = new();
    public List<string> AddedSerials { get; set; } = new();
    public List<string> RemovedSerials { get; set; } = new();
}

public sealed class LoginRequest
{
    public ulong SlotId { get; set; }
    public long Generation { get; set; }
    public string Pin { get; set; } = "";
}

public sealed class SlotRequest
{
    public ulong SlotId { get; set; }
    public long Generation { get; set; }
}

public sealed class SignRequest
{
    public ulong SlotId { get; set; }
    public long Generation { get; set; }
    public byte[] KeyId { get; set; } = Array.Empty<byte>();
    /// <summary>Raw CKM_* mechanism value (e.g. CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS).</summary>
    public ulong Mechanism { get; set; }
    public PssParamsDto? Pss { get; set; }
    public byte[] Data { get; set; } = Array.Empty<byte>();
}

public sealed class PssParamsDto
{
    public ulong HashAlg { get; set; }
    public ulong Mgf { get; set; }
    public ulong SaltLength { get; set; }
}

public sealed class SignResponse
{
    public byte[] Signature { get; set; } = Array.Empty<byte>();
}

public sealed class PortRequest
{
    public int Port { get; set; }
}

public sealed class CertificateBlob
{
    public int Port { get; set; }
    public byte[] Der { get; set; } = Array.Empty<byte>();
    public string Subject { get; set; } = "";
    public string Thumbprint { get; set; } = "";
}

public sealed class CertificateBlobList
{
    public List<CertificateBlob> Items { get; set; } = new();
}

public sealed class PingDto
{
    public long Ticks { get; set; }
    public string Machine { get; set; } = "";
    public string Role { get; set; } = "";
}

public sealed class WaitEventRequest
{
    public long KnownGeneration { get; set; }
    public int TimeoutMs { get; set; }
}

public sealed class EmptyDto { }

/// <summary>RPC envelope carried inside RPC request / response frames.</summary>
public sealed class RpcEnvelope
{
    public long Id { get; set; }
    public string Method { get; set; } = "";
    public byte[]? Body { get; set; }
    /// <summary>0 = success; otherwise a CKR_* value (PKCS#11) or one of <see cref="RpcErrors"/>.</summary>
    public ulong ErrorCode { get; set; }
    public string? Error { get; set; }
}

public static class RpcErrors
{
    /// <summary>Generic error that is not a PKCS#11 return value.</summary>
    public const ulong Internal = 0xDC500001;
    public const ulong NotConnected = 0xDC500002;
    public const ulong UnknownMethod = 0xDC500003;
    public const ulong Timeout = 0xDC500004;
}

public static class RpcMethods
{
    public const string Ping = "Ping";
    public const string GetTokenState = "GetTokenState";
    public const string Login = "Login";
    public const string Logout = "Logout";
    public const string Sign = "Sign";
    public const string GetEmSignerCertificates = "GetEmSignerCertificates";
    /// <summary>P11 pipe only: blocks until the token generation differs from the known one.</summary>
    public const string WaitEvent = "WaitEvent";
    /// <summary>P11 pipe only: is the tunnel to the Local PC connected?</summary>
    public const string Status = "Status";
}

public sealed class LinkStatusDto
{
    public bool Connected { get; set; }
    public string Transport { get; set; } = "";
    public string Peer { get; set; } = "";
}

public sealed class RpcException : Exception
{
    public ulong Code { get; }
    public RpcException(ulong code, string message) : base(message) { Code = code; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = false)]
[JsonSerializable(typeof(RpcEnvelope))]
[JsonSerializable(typeof(TokenStateDto))]
[JsonSerializable(typeof(TokenEventDto))]
[JsonSerializable(typeof(LoginRequest))]
[JsonSerializable(typeof(SlotRequest))]
[JsonSerializable(typeof(SignRequest))]
[JsonSerializable(typeof(SignResponse))]
[JsonSerializable(typeof(PortRequest))]
[JsonSerializable(typeof(CertificateBlob))]
[JsonSerializable(typeof(CertificateBlobList))]
[JsonSerializable(typeof(PingDto))]
[JsonSerializable(typeof(WaitEventRequest))]
[JsonSerializable(typeof(EmptyDto))]
[JsonSerializable(typeof(LinkStatusDto))]
[JsonSerializable(typeof(HelloDto))]
[JsonSerializable(typeof(ProofDto))]
public sealed partial class ProtocolJson : JsonSerializerContext
{
    public static byte[] Serialize<T>(T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
        => JsonSerializer.SerializeToUtf8Bytes(value, info);

    public static T Deserialize<T>(ReadOnlySpan<byte> data, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
        => JsonSerializer.Deserialize(data, info) ?? throw new InvalidDataException($"Empty {typeof(T).Name} payload");
}

public sealed class HelloDto
{
    public int Version { get; set; }
    public string Role { get; set; } = "";
    public string Machine { get; set; } = "";
    public string User { get; set; } = "";
    public byte[] Nonce { get; set; } = Array.Empty<byte>();
    public byte[] Salt { get; set; } = Array.Empty<byte>();
}

public sealed class ProofDto
{
    public byte[] Mac { get; set; } = Array.Empty<byte>();
}
