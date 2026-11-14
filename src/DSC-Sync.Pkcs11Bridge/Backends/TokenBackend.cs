using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;

namespace DscSync.Pkcs11Bridge.Backends;

/// <summary>Source of physical (or simulated) tokens on the Local PC. Implementations need not be thread-safe;
/// <see cref="TokenManager"/> serializes every call.</summary>
public interface ITokenBackend : IDisposable
{
    string Name { get; }
    /// <summary>Lists tokens currently present. Must not throw for "no token".</summary>
    IReadOnlyList<TokenInfoDto> Enumerate();
    /// <summary>Cleanly finalizes and unloads every vendor library, then re-discovers / reloads them.</summary>
    void Reload();
    void Login(ulong slotId, string pin);
    void Logout(ulong slotId);
    /// <summary>Throws <see cref="RpcException"/> with a CKR_* code on failure.</summary>
    byte[] Sign(ulong slotId, byte[] keyId, ulong mechanism, PssParamsDto? pss, byte[] data);
}

public static class CertificateMetadata
{
    private static readonly (string Needle, string Name)[] KnownCAs =
    {
        ("emudhra", "eMudhra"), ("capricorn", "Capricorn"), ("pantasign", "Pantasign"), ("vsign", "Vsign (Verasys)"),
        ("verasys", "Vsign (Verasys)"), ("ncode", "nCode"), ("safescrypt", "SafeScrypt (Sify)"), ("idsign", "IDSign"),
        ("xtra trust", "XtraTrust"), ("xtratrust", "XtraTrust"), ("care4sign", "Care4Sign"), ("prodigisign", "ProDigiSign"),
        ("speedsign", "SpeedSign"), ("cdac", "C-DAC"), ("idrbt", "IDRBT"), ("ncodesolutions", "nCode"),
        ("cca india", "CCA India"), ("india pki", "India PKI"),
    };

    public static CertificateDto FromDer(byte[] der, byte[] id, string label, bool hasPrivateKey)
    {
        using var x = new X509Certificate2(der);
        using var rsa = x.GetRSAPublicKey();
        var p = rsa?.ExportParameters(false);
        return new CertificateDto
        {
            Id = id,
            Label = label,
            Der = der,
            Subject = x.Subject,
            SubjectCommonName = x.GetNameInfo(X509NameType.SimpleName, false),
            Organization = ReadRdn(x.SubjectName, "2.5.4.10"),
            Issuer = x.Issuer,
            IssuerCommonName = FriendlyIssuer(x),
            SerialNumber = x.SerialNumber,
            Thumbprint = x.Thumbprint,
            NotBefore = x.NotBefore.ToUniversalTime(),
            NotAfter = x.NotAfter.ToUniversalTime(),
            KeySizeBits = rsa?.KeySize ?? 0,
            Modulus = p?.Modulus ?? Array.Empty<byte>(),
            PublicExponent = p?.Exponent ?? Array.Empty<byte>(),
            HasPrivateKey = hasPrivateKey,
        };
    }

    public static string FriendlyIssuer(X509Certificate2 x)
    {
        var cn = x.GetNameInfo(X509NameType.SimpleName, true);
        var all = (x.Issuer + " " + cn).ToLowerInvariant();
        foreach (var (needle, name) in KnownCAs)
            if (all.Contains(needle)) return $"{name} — {cn}";
        return cn;
    }

    public static string ReadRdn(X500DistinguishedName name, string oid)
    {
        try
        {
            foreach (var rdn in name.EnumerateRelativeDistinguishedNames())
                if (rdn.GetSingleElementType().Value == oid) return rdn.GetSingleElementValue() ?? "";
        }
        catch (CryptographicException) { }
        return "";
    }

    /// <summary>Is the cert usable for signing (digitalSignature or nonRepudiation)?</summary>
    public static bool IsSigningCertificate(byte[] der)
    {
        using var x = new X509Certificate2(der);
        var ku = x.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        return ku is null || (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
    }
}

/// <summary>Encodes / decodes PKCS#1 DigestInfo structures and maps hash algorithms to PKCS#11 constants.</summary>
public static class DigestInfo
{
    public static readonly (HashAlgorithmName Name, string Oid, int Length, ulong Ckm, ulong Mgf)[] Algorithms =
    {
        (HashAlgorithmName.SHA1, "1.3.14.3.2.26", 20, CKM.SHA_1, CKG.MGF1_SHA1),
        (HashAlgorithmName.SHA256, "2.16.840.1.101.3.4.2.1", 32, CKM.SHA256, CKG.MGF1_SHA256),
        (HashAlgorithmName.SHA384, "2.16.840.1.101.3.4.2.2", 48, CKM.SHA384, CKG.MGF1_SHA384),
        (HashAlgorithmName.SHA512, "2.16.840.1.101.3.4.2.3", 64, CKM.SHA512, CKG.MGF1_SHA512),
    };

    public static byte[] Encode(HashAlgorithmName alg, ReadOnlySpan<byte> hash)
    {
        var a = Algorithms.First(x => x.Name == alg);
        if (hash.Length != a.Length) throw new CryptographicException($"Invalid {alg.Name} hash length {hash.Length}");
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(a.Oid);
                w.WriteNull();
            }
            w.WriteOctetString(hash);
        }
        return w.Encode();
    }

    public static bool TryDecode(byte[] data, out HashAlgorithmName alg, out byte[] hash)
    {
        alg = default;
        hash = Array.Empty<byte>();
        try
        {
            var r = new AsnReader(data, AsnEncodingRules.DER);
            var seq = r.ReadSequence();
            var algSeq = seq.ReadSequence();
            var oid = algSeq.ReadObjectIdentifier();
            if (algSeq.HasData) algSeq.ReadNull();
            var h = seq.ReadOctetString();
            if (seq.HasData || r.HasData) return false;
            foreach (var a in Algorithms)
            {
                if (a.Oid == oid && h.Length == a.Length) { alg = a.Name; hash = h; return true; }
            }
        }
        catch (AsnContentException) { }
        return false;
    }

    public static HashAlgorithmName FromCkm(ulong ckmHash)
    {
        foreach (var a in Algorithms)
            if (a.Ckm == ckmHash) return a.Name;
        throw new RpcException(CKR.MECHANISM_PARAM_INVALID, $"Unsupported hash 0x{ckmHash:X}");
    }

    public static HashAlgorithmName FromHashingMechanism(ulong mech) => mech switch
    {
        CKM.SHA1_RSA_PKCS or CKM.SHA1_RSA_PKCS_PSS => HashAlgorithmName.SHA1,
        CKM.SHA256_RSA_PKCS or CKM.SHA256_RSA_PKCS_PSS => HashAlgorithmName.SHA256,
        CKM.SHA384_RSA_PKCS or CKM.SHA384_RSA_PKCS_PSS => HashAlgorithmName.SHA384,
        CKM.SHA512_RSA_PKCS or CKM.SHA512_RSA_PKCS_PSS => HashAlgorithmName.SHA512,
        _ => throw new RpcException(CKR.MECHANISM_INVALID, $"Mechanism {CKM.Name(mech)} is not a hashing mechanism"),
    };

    public static PssParamsDto PssFor(HashAlgorithmName alg)
    {
        var a = Algorithms.First(x => x.Name == alg);
        return new PssParamsDto { HashAlg = a.Ckm, Mgf = a.Mgf, SaltLength = (ulong)a.Length };
    }
}
