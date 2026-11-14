namespace DscSync.Pkcs11Bridge.Backends;

public sealed record VendorLibrary(string Vendor, string FileName);

/// <summary>Finds PKCS#11 middleware DLLs installed by Indian DSC token vendors.</summary>
public static class VendorLibraryLocator
{
    public static readonly VendorLibrary[] KnownLibraries =
    {
        new("ePass2003 (Feitian) FIPS 140-3", "eps2003csp11v2.dll"),
        new("ePass2003 (Feitian)", "eps2003csp11.dll"),
        new("ProxKey (Watchdata)", "wdpkcs.dll"),
        new("ProxKey (Watchdata)", "SignatureP11.dll"),
        new("TrustKey", "castle.dll"),
        new("TrustKey", "TrustKeyP11.dll"),
        new("SafeSign (A.E.T.)", "aetpkss1.dll"),
        new("mToken (Longmai)", "mtoken_pkcs11.dll"),
        new("mToken CryptoID (Longmai)", "CryptoIDA_pkcs11.dll"),
        new("Gemalto SafeNet eToken", "eTPKCS11.dll"),
        new("HYP2003 (Feitian)", "hypersecu_pkcs11.dll"),
        new("Bit4id", "bit4ipki.dll"),
        new("SecureMetric", "smartpkcs11.dll"),
    };

    private static readonly string[] VendorDirectories =
    {
        @"EnterSafe\ePass2003", @"ePass2003", @"Watchdata\ProxKey", @"Watchdata", @"ProxKey", @"TrustKey", @"Castle",
        @"A.E.T. Europe B.V.\SafeSign", @"SafeSign", @"mToken", @"Longmai", @"SafeNet\Authentication\SAC\x64",
        @"Gemalto\IDGo 800 PKCS#11", @"HyperSecu", @"Bit4id",
    };

    /// <summary>Returns existing library paths: explicit overrides first, then auto-discovered vendor DLLs.</summary>
    public static IReadOnlyList<(string Path, string Vendor)> Discover(IEnumerable<string>? overrides = null)
    {
        var found = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string path, string vendor)
        {
            try
            {
                var full = Path.GetFullPath(path);
                if (File.Exists(full) && seen.Add(full)) found.Add((full, vendor));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        }

        foreach (var o in overrides ?? Array.Empty<string>())
            if (!string.IsNullOrWhiteSpace(o)) Add(Environment.ExpandEnvironmentVariables(o), VendorFor(Path.GetFileName(o)));

        if (!OperatingSystem.IsWindows()) return found;

        // System32 resolves to SysWOW64 automatically for 32-bit processes thanks to WOW64 redirection.
        var searchDirs = new List<string> { Environment.SystemDirectory };
        foreach (var root in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 })
        {
            if (string.IsNullOrEmpty(root)) continue;
            foreach (var d in VendorDirectories) searchDirs.Add(Path.Combine(root, d));
        }

        foreach (var lib in KnownLibraries)
            foreach (var dir in searchDirs)
                Add(Path.Combine(dir, lib.FileName), lib.Vendor);
        return found;
    }

    public static string VendorFor(string fileName) =>
        KnownLibraries.FirstOrDefault(l => l.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase))?.Vendor
        ?? Path.GetFileNameWithoutExtension(fileName);
}
