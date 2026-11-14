using System.Security.Cryptography;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge.Backends;

namespace DscSync.Pkcs11Bridge.Crypto;

/// <summary>
/// An <see cref="RSA"/> whose private-key operation executes on the DSC token (local or through the tunnel).
/// Lets standard .NET APIs (SignedCms, iText, …) sign with a token that is physically on another PC.
/// </summary>
public sealed class TokenRsa : RSA
{
    private readonly ITokenClient _client;
    private readonly TokenInfoDto _token;
    private readonly CertificateDto _certificate;
    private readonly RSA _public;
    private readonly long _generation;

    public TokenRsa(ITokenClient client, TokenInfoDto token, CertificateDto certificate)
    {
        _client = client;
        _token = token;
        _certificate = certificate;
        _generation = client.State.Generation;
        _public = RSA.Create();
        _public.ImportParameters(new RSAParameters { Modulus = certificate.Modulus, Exponent = certificate.PublicExponent });
        KeySizeValue = _public.KeySize;
        LegalKeySizesValue = new[] { new KeySizes(1024, 8192, 8) };
    }

    public CertificateDto Certificate => _certificate;
    public TokenInfoDto Token => _token;

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters) throw new CryptographicException("The private key never leaves the DSC token");
        return _public.ExportParameters(false);
    }

    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException("Token-backed keys cannot be replaced");

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        SignRequest req;
        if (padding == RSASignaturePadding.Pkcs1)
        {
            req = new SignRequest { Mechanism = CKM.RSA_PKCS, Data = DigestInfo.Encode(hashAlgorithm, hash) };
        }
        else if (padding == RSASignaturePadding.Pss)
        {
            req = new SignRequest { Mechanism = CKM.RSA_PKCS_PSS, Pss = DigestInfo.PssFor(hashAlgorithm), Data = hash };
        }
        else
        {
            throw new CryptographicException("Unsupported padding " + padding);
        }
        req.SlotId = _token.SlotId;
        req.Generation = _generation;
        req.KeyId = _certificate.Id;
        try
        {
            return _client.SignAsync(req).GetAwaiter().GetResult();
        }
        catch (RpcException ex)
        {
            throw new CryptographicException($"Token signing failed: {ex.Message} (CKR 0x{ex.Code:X})", ex);
        }
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        => _public.VerifyHash(hash, signature, hashAlgorithm, padding);

    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => _public.Encrypt(data, padding);

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) =>
        throw new CryptographicException("DSC-Sync exposes signing keys only");

    protected override void Dispose(bool disposing)
    {
        if (disposing) _public.Dispose();
        base.Dispose(disposing);
    }
}
