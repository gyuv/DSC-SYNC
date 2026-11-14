using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using DscSync.Core;
using DscSync.Core.Config;
using DscSync.Pkcs11Bridge.Backends;
using DscSync.Pkcs11Bridge.Crypto;
using DscSync.Tunnel.Proxy;

namespace DscSync.App.Services;

public enum Health { Ok, Warn, Bad, Info }

public sealed record HealthItem(string Name, Health Status, string Detail)
{
    public string Badge => Status switch { Health.Ok => "●", Health.Warn => "▲", Health.Bad => "✖", _ => "ℹ" };
    public string Color => Status switch { Health.Ok => "#22C55E", Health.Warn => "#F59E0B", Health.Bad => "#EF4444", _ => "#3B82F6" };
}

/// <summary>Health checks and one-click fixes for the common Indian portal / RDP signing blockers.</summary>
public sealed class Diagnostics
{
    private readonly SyncController _sync;

    public Diagnostics(SyncController sync) => _sync = sync;

    public async Task<List<HealthItem>> CheckAsync()
    {
        var items = new List<HealthItem>();
        var cfg = _sync.Config;
        var link = _sync.Link;
        items.Add(link is null
            ? new HealthItem("Link", Health.Bad, cfg.Mode == SyncMode.Local
                ? "Waiting for the Remote Desktop session (connect with mstsc) or TLS tunnel"
                : "Waiting for your Local PC (start DSC-Sync on it in Local mode, then reconnect RDP)")
            : new HealthItem("Link", Health.Ok, $"{link.Transport} → {link.Peer}"));

        var tokens = _sync.State.Tokens;
        items.Add(tokens.Count == 0
            ? new HealthItem("DSC token", Health.Bad, cfg.Mode == SyncMode.Local ? "No token detected — insert your USB DSC" : "No token synced from Local PC")
            : new HealthItem("DSC token", Health.Ok, string.Join("; ", tokens.Select(t => $"{t.Certificates.FirstOrDefault()?.SubjectCommonName} ({t.Vendor})"))));

        foreach (var c in tokens.SelectMany(t => t.Certificates))
        {
            var days = (c.NotAfter - DateTime.UtcNow).TotalDays;
            if (days < 30)
                items.Add(new HealthItem("Certificate expiry", days < 0 ? Health.Bad : Health.Warn, $"{c.SubjectCommonName} expires {c.NotAfter.ToLocalTime():dd-MMM-yyyy}"));
        }

        if (cfg.Mode == SyncMode.Local)
        {
            if (!cfg.UseSimulatedToken)
            {
                var libs = VendorLibraryLocator.Discover(cfg.VendorLibraries);
                items.Add(libs.Count == 0
                    ? new HealthItem("Token driver", Health.Bad, "No DSC token driver (ePass2003 / ProxKey / TrustKey / SafeSign / mToken) found. Install the driver that came with your token.")
                    : new HealthItem("Token driver", Health.Ok, string.Join(", ", libs.Select(l => l.Vendor).Distinct())));
            }
            var listening = new List<int>();
            foreach (var p in cfg.EmSignerPorts)
                if (await LocalPortScanner.IsListeningAsync(p)) listening.Add(p);
            items.Add(listening.Count == 0
                ? new HealthItem("emSigner (this PC)", Health.Warn, "emSigner is not running here. Start it for GST / MCA / Income Tax signing (PDF signing still works).")
                : new HealthItem("emSigner (this PC)", Health.Ok, "Listening on " + string.Join(", ", listening)));
            items.Add(Installer.IsRdpPluginRegistered()
                ? new HealthItem("RDP plug-in", Health.Ok, "Registered with Remote Desktop Connection (mstsc)")
                : new HealthItem("RDP plug-in", Health.Warn, "Not registered — click Auto-Fix, then reconnect Remote Desktop"));
        }
        else
        {
            var owners = WinNative.ListenerOwners();
            foreach (var port in cfg.EmSignerPorts)
            {
                var mine = _sync.Remote?.PortStatus.FirstOrDefault(s => s.Port == port && s.State == PortState.Listening);
                if (mine is not null) { items.Add(new HealthItem($"Port {port}", Health.Ok, "Routed to Local PC (this session runs the port router)")); continue; }
                if (!owners.TryGetValue(port, out var pid)) { items.Add(new HealthItem($"Port {port}", Health.Bad, "Not served — click Auto-Fix")); continue; }
                var name = WinNative.ProcessName(pid);
                items.Add(name.StartsWith("DSC-Sync", StringComparison.OrdinalIgnoreCase)
                    ? new HealthItem($"Port {port}", Health.Ok, $"Shared router (session {SessionInfo.ResolveSession(pid)}) → your Local PC")
                    : new HealthItem($"Port {port}", Health.Bad, $"Blocked by {name} — click Auto-Fix"));
            }
            var trusted = _sync.Remote?.TrustedCertificates ?? Array.Empty<DscSync.Core.Protocol.CertificateBlob>();
            items.Add(trusted.Count == 0
                ? new HealthItem("emSigner SSL trust", Health.Warn, "Local emSigner certificate not synced yet (start emSigner on the Local PC)")
                : trusted.All(t => CertificateTrust.IsTrusted(t.Thumbprint))
                    ? new HealthItem("emSigner SSL trust", Health.Ok, "127.0.0.1 certificate trusted by Chrome / Edge")
                    : new HealthItem("emSigner SSL trust", Health.Bad, "Certificate not trusted — click Auto-Fix"));
            items.Add(File.Exists(Installer.P11x64)
                ? new HealthItem("PKCS#11 module", Health.Info, $"For Adobe Acrobat: Preferences ▸ Signatures ▸ Identities ▸ PKCS#11 Modules ▸ Attach: {Installer.P11x64}")
                : new HealthItem("PKCS#11 module", Health.Warn, "DSC-Sync-P11-x64.dll missing next to DSC-Sync.exe"));
            items.Add(new HealthItem("PKCS#11 clients", Health.Info, $"{_sync.Remote?.P11Clients ?? 0} application(s) connected"));
        }

        items.Add(SmartCardService());
        return items;
    }

    private static HealthItem SmartCardService()
    {
        try
        {
            using var sc = new ServiceController("SCardSvr");
            return sc.Status == ServiceControllerStatus.Running
                ? new HealthItem("Smart Card service", Health.Ok, "SCardSvr running")
                : new HealthItem("Smart Card service", Health.Warn, $"SCardSvr is {sc.Status} — Auto-Fix restarts it (admin)");
        }
        catch (Exception) { return new HealthItem("Smart Card service", Health.Info, "SCardSvr not installed"); }
    }

    /// <summary>Repairs what can be repaired and returns a human-readable report.</summary>
    public async Task<string> AutoFixAsync(string? tokenPin)
    {
        var report = new StringBuilder();
        var cfg = _sync.Config;
        if (cfg.Mode == SyncMode.Local)
        {
            report.AppendLine(Installer.RegisterRdpPlugin(m => report.AppendLine(m)) ? "✔ RDP plug-in registered (reconnect Remote Desktop to activate)" : "✖ RDP plug-in not registered");
            _sync.Tokens?.Rescan(reload: true);
            report.AppendLine($"✔ Token middleware reloaded — {_sync.State.Tokens.Count} token(s) present");
        }
        else if (_sync.Remote is { } remote)
        {
            await remote.RebindPortsAsync();
            report.AppendLine("✔ Conflicting emSigner / Java processes in this session stopped and ports re-bound");
            int trusted = await remote.SyncCertificatesAsync();
            report.AppendLine(trusted > 0 ? $"✔ {trusted} emSigner certificate(s) trusted for 127.0.0.1" : "▲ No emSigner certificate synced (is emSigner running on the Local PC?)");
            try
            {
                var latency = await remote.PingAsync();
                report.AppendLine($"✔ Link round-trip {latency.TotalMilliseconds:F0} ms");
            }
            catch (Exception ex) { report.AppendLine("✖ Link test failed: " + ex.Message); }
        }

        var sc = SmartCardService();
        if (sc.Status == Health.Warn)
            report.AppendLine(Installer.RestartSmartCardService() ? "✔ Smart Card service restarted" : "▲ Smart Card service restart needs administrator approval");

        report.AppendLine(await SignatureRoundTripAsync(tokenPin));
        return report.ToString();
    }

    /// <summary>Signs a random SHA-256 digest with the synced token and verifies it with the certificate.</summary>
    public async Task<string> SignatureRoundTripAsync(string? pin)
    {
        var client = _sync.Client;
        var token = _sync.State.Tokens.FirstOrDefault();
        var cert = token?.Certificates.FirstOrDefault();
        if (client is null || token is null || cert is null) return "▲ Signature test skipped: no token";
        if (string.IsNullOrEmpty(pin)) return "▲ Signature test skipped: enter the token PIN to run it";
        try
        {
            await client.LoginAsync(token.SlotId, _sync.State.Generation, pin);
            using var rsa = new TokenRsa(client, token, cert);
            var digest = SHA256.HashData(RandomNumberGenerator.GetBytes(64));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var sig = await Task.Run(() => rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            bool ok = rsa.VerifyHash(digest, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return ok ? $"✔ SHA-256 signature round-trip OK ({sw.ElapsedMilliseconds} ms) with {cert.SubjectCommonName}"
                      : "✖ Signature returned but did not verify";
        }
        catch (Exception ex) { return "✖ Signature test failed: " + ex.Message; }
    }

    public static string Format(IEnumerable<HealthItem> items) =>
        string.Join(Environment.NewLine, items.Select(i => $"[{i.Status}] {i.Name}: {i.Detail}"));
}
