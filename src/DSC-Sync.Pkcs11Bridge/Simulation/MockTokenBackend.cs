using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge.Backends;

namespace DscSync.Pkcs11Bridge.Simulation;

/// <summary>A simulated Class-3 DSC token with a CA-issued RSA certificate (used by tests and "demo mode").</summary>
public sealed class MockToken : IDisposable
{
    public required string Serial { get; init; }
    public required string Vendor { get; init; }
    public required string Pin { get; init; }
    public required RSA Key { get; init; }
    public required byte[] CertificateDer { get; init; }
    public byte[] KeyId { get; init; } = RandomNumberGenerator.GetBytes(20);
    public int FailedLogins { get; set; }

    public static MockToken Create(string commonName, string serial, string vendor = "ePass2003 (Simulated)", string pin = "12345678",
        string organization = "Demo Enterprises Pvt Ltd", string caName = "e-Mudhra Sub CA for Class 3 Individual 2022", int keyBits = 2048)
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest($"CN={caName}, O=eMudhra Limited, C=IN", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddYears(10));

        var key = RSA.Create(keyBits);
        var req = new CertificateRequest($"CN={commonName}, O={organization}, C=IN", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        var serialBytes = RandomNumberGenerator.GetBytes(8);
        serialBytes[0] &= 0x7F;
        using var leaf = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serialBytes);
        return new MockToken { Serial = serial, Vendor = vendor, Pin = pin, Key = key, CertificateDer = leaf.RawData };
    }

    public X509Certificate2 Certificate => new(CertificateDer);

    public void Dispose() => Key.Dispose();
}

/// <summary>In-memory backend emulating PKCS#11 hot-plug semantics (slot ids stay stable per insertion).</summary>
public sealed class MockTokenBackend : ITokenBackend
{
    private readonly object _lock = new();
    private readonly List<(ulong Slot, MockToken Token)> _inserted = new();
    private readonly HashSet<ulong> _loggedIn = new();
    private ulong _nextSlot = 1;

    public string Name => "Simulated token";
    public int ReloadCount { get; private set; }
    public int SignCount { get; private set; }

    public void Insert(MockToken token)
    {
        lock (_lock) _inserted.Add((_nextSlot++, token));
    }

    public bool Remove(string serial)
    {
        lock (_lock)
        {
            int idx = _inserted.FindIndex(t => t.Token.Serial == serial);
            if (idx < 0) return false;
            _loggedIn.Remove(_inserted[idx].Slot);
            _inserted.RemoveAt(idx);
            return true;
        }
    }

    public IReadOnlyList<TokenInfoDto> Enumerate()
    {
        lock (_lock)
        {
            return _inserted.Select(t => new TokenInfoDto
            {
                SlotId = t.Slot,
                Vendor = t.Token.Vendor,
                LibraryPath = "mock://" + t.Token.Vendor,
                Label = "DSC Token",
                Model = "Simulated",
                Manufacturer = "DSC-Sync",
                SerialNumber = t.Token.Serial,
                MinPinLength = 4,
                MaxPinLength = 16,
                Certificates = { CertificateMetadata.FromDer(t.Token.CertificateDer, t.Token.KeyId, "Signing Certificate", true) },
            }).ToList();
        }
    }

    public void Reload()
    {
        lock (_lock)
        {
            ReloadCount++;
            _loggedIn.Clear(); // a real C_Finalize drops every login
        }
    }

    public void Login(ulong slotId, string pin)
    {
        lock (_lock)
        {
            var t = Find(slotId);
            if (t.FailedLogins >= 10) throw new RpcException(CKR.PIN_LOCKED, "PIN locked");
            if (pin != t.Pin)
            {
                t.FailedLogins++;
                throw new RpcException(CKR.PIN_INCORRECT, "Incorrect PIN");
            }
            t.FailedLogins = 0;
            _loggedIn.Add(slotId);
        }
    }

    public void Logout(ulong slotId)
    {
        lock (_lock) _loggedIn.Remove(slotId);
    }

    public byte[] Sign(ulong slotId, byte[] keyId, ulong mechanism, PssParamsDto? pss, byte[] data)
    {
        lock (_lock)
        {
            var t = Find(slotId);
            if (!_loggedIn.Contains(slotId)) throw new RpcException(CKR.USER_NOT_LOGGED_IN, "Login required");
            if (!keyId.AsSpan().SequenceEqual(t.KeyId)) throw new RpcException(CKR.KEY_HANDLE_INVALID, "Key not found");
            SignCount++;
            return SoftwareSigner.Sign(t.Key, mechanism, pss, data);
        }
    }

    private MockToken Find(ulong slotId)
    {
        foreach (var (slot, token) in _inserted)
            if (slot == slotId) return token;
        throw new RpcException(CKR.TOKEN_NOT_PRESENT, "Token not present");
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var (_, t) in _inserted) t.Dispose();
            _inserted.Clear();
        }
    }
}

/// <summary>PKCS#11 signing semantics implemented with a software RSA key.</summary>
public static class SoftwareSigner
{
    public static byte[] Sign(RSA key, ulong mechanism, PssParamsDto? pss, byte[] data)
    {
        switch (mechanism)
        {
            case CKM.RSA_PKCS:
                return RawPkcs1Sign(key, data);
            case CKM.SHA1_RSA_PKCS:
            case CKM.SHA256_RSA_PKCS:
            case CKM.SHA384_RSA_PKCS:
            case CKM.SHA512_RSA_PKCS:
                return key.SignData(data, DigestInfo.FromHashingMechanism(mechanism), RSASignaturePadding.Pkcs1);
            case CKM.RSA_PKCS_PSS:
                {
                    if (pss is null) throw new RpcException(CKR.MECHANISM_PARAM_INVALID, "PSS params required");
                    var alg = DigestInfo.FromCkm(pss.HashAlg);
                    CheckPssSalt(alg, pss);
                    return key.SignHash(data, alg, RSASignaturePadding.Pss);
                }
            case CKM.SHA1_RSA_PKCS_PSS:
            case CKM.SHA256_RSA_PKCS_PSS:
            case CKM.SHA384_RSA_PKCS_PSS:
            case CKM.SHA512_RSA_PKCS_PSS:
                {
                    var alg = DigestInfo.FromHashingMechanism(mechanism);
                    if (pss is not null) CheckPssSalt(alg, pss);
                    return key.SignData(data, alg, RSASignaturePadding.Pss);
                }
            default:
                throw new RpcException(CKR.MECHANISM_INVALID, $"Unsupported mechanism {CKM.Name(mechanism)}");
        }
    }

    private static void CheckPssSalt(HashAlgorithmName alg, PssParamsDto pss)
    {
        var expected = DigestInfo.PssFor(alg);
        if (pss.SaltLength != expected.SaltLength || pss.Mgf != expected.Mgf)
            throw new RpcException(CKR.MECHANISM_PARAM_INVALID, "Only MGF1 with salt length = hash length is supported");
    }

    /// <summary>CKM_RSA_PKCS: EMSA-PKCS1-v1_5 block type 1 padding of arbitrary data, then RSASP1.</summary>
    private static byte[] RawPkcs1Sign(RSA key, byte[] data)
    {
        int k = key.KeySize / 8;
        if (data.Length > k - 11) throw new RpcException(CKR.DATA_LEN_RANGE, "Data too long for key");
        if (DigestInfo.TryDecode(data, out var alg, out var hash))
            return key.SignHash(hash, alg, RSASignaturePadding.Pkcs1);
        var p = key.ExportParameters(true);
        var em = new byte[k];
        em[1] = 0x01;
        for (int i = 2; i < k - data.Length - 1; i++) em[i] = 0xFF;
        data.CopyTo(em, k - data.Length);
        var m = new BigInteger(em, isUnsigned: true, isBigEndian: true);
        var n = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var d = new BigInteger(p.D, isUnsigned: true, isBigEndian: true);
        var s = BigInteger.ModPow(m, d, n).ToByteArray(isUnsigned: true, isBigEndian: true);
        var result = new byte[k];
        s.CopyTo(result, k - s.Length);
        return result;
    }
}
