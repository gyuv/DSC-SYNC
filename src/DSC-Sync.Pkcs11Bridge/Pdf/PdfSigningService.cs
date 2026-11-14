using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using iText.Forms.Form.Element;
using Rectangle = iText.Kernel.Geom.Rectangle;
using iText.Kernel.Pdf;
using iText.Signatures;

namespace DscSync.Pkcs11Bridge.Pdf;

public sealed class PdfSignOptions
{
    /// <summary>1-based page; 0 or negative = last page.</summary>
    public int PageNumber { get; set; }
    public bool Visible { get; set; } = true;
    /// <summary>Rectangle in PDF points from the bottom-left corner.</summary>
    public float X { get; set; } = 380;
    public float Y { get; set; } = 60;
    public float Width { get; set; } = 180;
    public float Height { get; set; } = 60;
    public string Reason { get; set; } = "Digitally signed";
    public string Location { get; set; } = "India";
    public string ContactInfo { get; set; } = "";
    public HashAlgorithmName Hash { get; set; } = HashAlgorithmName.SHA256;
}

public sealed class PdfSignResult
{
    public required string OutputPath { get; init; }
    public required string FieldName { get; init; }
    public required int Page { get; init; }
    public required string SignerName { get; init; }
}

/// <summary>
/// Signs a PDF with an adbe.pkcs7.detached CMS signature (accepted by Adobe Acrobat / Reader, MCA, GST uploads).
/// The private-key operation is delegated to the supplied <see cref="RSA"/> (normally a token-backed TokenRsa).
/// </summary>
public static class PdfSigningService
{
    public static int GetPageCount(string path)
    {
        using var reader = new PdfReader(path);
        using var doc = new PdfDocument(reader);
        return doc.GetNumberOfPages();
    }

    public static (float Width, float Height) GetPageSize(string path, int page)
    {
        using var reader = new PdfReader(path);
        using var doc = new PdfDocument(reader);
        int p = page <= 0 ? doc.GetNumberOfPages() : Math.Min(page, doc.GetNumberOfPages());
        var size = doc.GetPage(p).GetPageSize();
        return (size.GetWidth(), size.GetHeight());
    }

    public static PdfSignResult Sign(string inputPath, string outputPath, X509Certificate2 certificate, RSA privateKey, PdfSignOptions options)
    {
        if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Output file must differ from the input file");

        int pages = GetPageCount(inputPath);
        int page = options.PageNumber <= 0 || options.PageNumber > pages ? pages : options.PageNumber;
        string field = "DSCSync_" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
        string signer = certificate.GetNameInfo(X509NameType.SimpleName, false);
        var tmp = outputPath + ".partial";
        try
        {
            using (var reader = new PdfReader(inputPath))
            using (var output = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            {
                var pdfSigner = new PdfSigner(reader, output, new StampingProperties().UseAppendMode());
                pdfSigner.SetFieldName(field);
                pdfSigner.SetSignDate(DateTime.Now);
                pdfSigner.SetReason(options.Reason);
                pdfSigner.SetLocation(options.Location);
                pdfSigner.SetContact(options.ContactInfo);
                if (options.Visible)
                {
                    pdfSigner.SetPageNumber(page);
                    pdfSigner.SetPageRect(new Rectangle(options.X, options.Y, options.Width, options.Height));
                    var appearance = new SignatureFieldAppearance(field)
                        .SetContent($"Digitally signed by {signer}\nDate: {DateTime.Now:dd-MM-yyyy HH:mm:ss zzz}\nReason: {options.Reason}\nLocation: {options.Location}");
                    appearance.SetFontSize(7f);
                    pdfSigner.SetSignatureAppearance(appearance);
                }
                var container = new CmsSignatureContainer(certificate, privateKey, options.Hash);
                pdfSigner.SignExternalContainer(container, 8192 + certificate.RawData.Length * 2);
            }
            File.Move(tmp, outputPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
        return new PdfSignResult { OutputPath = outputPath, FieldName = field, Page = page, SignerName = signer };
    }

    /// <summary>Verifies every CMS signature in the PDF; returns (field, signer CN, valid) tuples.</summary>
    public static IReadOnlyList<(string Field, string Signer, bool Valid)> Verify(string path)
    {
        var results = new List<(string, string, bool)>();
        using var reader = new PdfReader(path);
        using var doc = new PdfDocument(reader);
        var util = new SignatureUtil(doc);
        foreach (var name in util.GetSignatureNames())
        {
            var sig = util.GetSignature(name);
            var contents = sig.GetContents().GetValueBytes();
            var range = sig.GetByteRange().ToLongArray();
            byte[] signedBytes;
            using (var raf = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var ms = new MemoryStream())
            {
                for (int i = 0; i < range.Length; i += 2)
                {
                    raf.Seek(range[i], SeekOrigin.Begin);
                    var buf = new byte[range[i + 1]];
                    raf.ReadExactly(buf);
                    ms.Write(buf);
                }
                signedBytes = ms.ToArray();
            }
            var cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
            int len = TrimDer(contents);
            cms.Decode(contents.AsSpan(0, len));
            bool ok;
            try { cms.CheckSignature(verifySignatureOnly: true); ok = true; }
            catch (CryptographicException) { ok = false; }
            results.Add((name, cms.SignerInfos[0].Certificate?.GetNameInfo(X509NameType.SimpleName, false) ?? "", ok));
        }
        return results;
    }

    private static int TrimDer(byte[] data)
    {
        // /Contents is zero padded; compute the real DER length from the outer SEQUENCE header.
        if (data.Length < 2 || data[0] != 0x30) return data.Length;
        int lenByte = data[1];
        if (lenByte < 0x80) return 2 + lenByte;
        int n = lenByte & 0x7F, len = 0;
        for (int i = 0; i < n; i++) len = (len << 8) | data[2 + i];
        return 2 + n + len;
    }

    private sealed class CmsSignatureContainer : IExternalSignatureContainer
    {
        private readonly X509Certificate2 _certificate;
        private readonly RSA _key;
        private readonly HashAlgorithmName _hash;

        public CmsSignatureContainer(X509Certificate2 certificate, RSA key, HashAlgorithmName hash)
        {
            _certificate = certificate;
            _key = key;
            _hash = hash;
        }

        public byte[] Sign(Stream data)
        {
            using var ms = new MemoryStream();
            data.CopyTo(ms);
            var cms = new SignedCms(new ContentInfo(ms.ToArray()), detached: true);
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, _certificate, _key)
            {
                DigestAlgorithm = new Oid(_hash == HashAlgorithmName.SHA512 ? "2.16.840.1.101.3.4.2.3"
                    : _hash == HashAlgorithmName.SHA384 ? "2.16.840.1.101.3.4.2.2" : "2.16.840.1.101.3.4.2.1"),
                IncludeOption = X509IncludeOption.EndCertOnly,
            };
            signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            cms.ComputeSignature(signer, silent: true);
            return cms.Encode();
        }

        public void ModifySigningDictionary(PdfDictionary signDic)
        {
            signDic.Put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.Put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
        }
    }
}
