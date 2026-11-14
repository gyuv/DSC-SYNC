using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using DscSync.Core.Config;
using Microsoft.Win32;

namespace DscSync.App.Services;

/// <summary>Per-user (no admin) installation helpers plus optional admin-only machine-wide options.</summary>
public static class Installer
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RdpAddInKey = @"Software\Microsoft\Terminal Server Client\Default\AddIns\DSCSync";
    public const string ServiceName = "DSC-Sync";

    public static string ExePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "DSC-Sync.exe");
    public static string AppDir => AppContext.BaseDirectory;
    public static string P11x64 => Path.Combine(AppDir, "DSC-Sync-P11-x64.dll");
    public static string P11x86 => Path.Combine(AppDir, "DSC-Sync-P11-x86.dll");
    public static string RdpPlugin => Path.Combine(AppDir, "DSC-Sync-RdpPlugin.dll");

    public static bool IsAutoStartEnabled()
    {
        using var k = Registry.CurrentUser.OpenSubKey(RunKey);
        return k?.GetValue("DSC-Sync") is string;
    }

    public static void SetAutoStart(bool enabled)
    {
        using var k = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled) k.SetValue("DSC-Sync", $"\"{ExePath}\" --minimized");
        else k.DeleteValue("DSC-Sync", false);
    }

    /// <summary>Registers the native DVC plug-in with mstsc for this user (takes effect on the next RDP connection).</summary>
    public static bool RegisterRdpPlugin(Action<string> log)
    {
        if (!File.Exists(RdpPlugin))
        {
            log("RDP plug-in DLL not found next to DSC-Sync.exe; using TLS tunnel only");
            return false;
        }
        using var k = Registry.CurrentUser.CreateSubKey(RdpAddInKey);
        k.SetValue("Name", RdpPlugin);
        return true;
    }

    public static bool IsRdpPluginRegistered()
    {
        using var k = Registry.CurrentUser.OpenSubKey(RdpAddInKey);
        return k?.GetValue("Name") is string s && string.Equals(s, RdpPlugin, StringComparison.OrdinalIgnoreCase) && File.Exists(s);
    }

    public static void UnregisterRdpPlugin() => Registry.CurrentUser.DeleteSubKeyTree(RdpAddInKey, false);

    /// <summary>Admin: start DSC-Sync automatically for every user who logs on to this server.</summary>
    public static bool EnableForAllUsers() => RunElevated("reg.exe",
        $"add \"HKLM\\{RunKey}\" /v DSC-Sync /t REG_SZ /d \"\\\"{ExePath}\\\" --minimized\" /f");

    /// <summary>Admin: background Windows service for a headless Local PC (TLS tunnel transport).</summary>
    public static bool InstallService() => RunElevated("sc.exe",
        $"create {ServiceName} binPath= \"\\\"{ExePath}\\\" --service\" start= auto DisplayName= \"DSC-Sync Token Bridge\"");

    public static bool UninstallService() => RunElevated("sc.exe", $"delete {ServiceName}");

    public static bool RestartSmartCardService() => RunElevated("cmd.exe", "/c net stop SCardSvr /y & net start SCardSvr");

    public static bool RunElevated(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args) { Verb = "runas", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden });
            p?.WaitForExit(30_000);
            return p?.ExitCode == 0;
        }
        catch (Exception) { return false; } // user cancelled UAC
    }

    public static void OpenFolder(string path)
    {
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true }); }
        catch (Exception) { }
    }
}

/// <summary>Rolling daily log for troubleshooting / bug reports (14 days kept).</summary>
public sealed class FileLog
{
    private readonly object _lock = new();
    public string Directory { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DSC-Sync", "logs");

    public FileLog()
    {
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            foreach (var f in System.IO.Directory.GetFiles(Directory, "*.log"))
                if (File.GetLastWriteTime(f) < DateTime.Now.AddDays(-14)) File.Delete(f);
        }
        catch (Exception) { }
    }

    public void Write(string message)
    {
        lock (_lock)
        {
            try { File.AppendAllText(Path.Combine(Directory, $"dsc-sync-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss.fff} {message}{Environment.NewLine}"); }
            catch (Exception) { }
        }
    }

    /// <summary>Creates a zip with logs + sanitized config + environment info on the Desktop.</summary>
    public string ExportSupportBundle(AppConfig config, string diagnostics)
    {
        var zipPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"DSC-Sync-support-{Environment.UserName}-{DateTime.Now:yyyyMMdd-HHmm}.zip");
        using var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create);
        foreach (var f in System.IO.Directory.GetFiles(Directory, "*.log"))
        {
            using var src = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var dst = zip.CreateEntry("logs/" + Path.GetFileName(f)).Open();
            src.CopyTo(dst);
        }
        var safe = config.Clone();
        safe.PairingPin = string.IsNullOrEmpty(safe.PairingPin) ? "" : "***";
        var info = new StringBuilder()
            .AppendLine($"Version: {typeof(FileLog).Assembly.GetName().Version}")
            .AppendLine($"OS: {Environment.OSVersion} 64-bit={Environment.Is64BitOperatingSystem}")
            .AppendLine($"Machine: {Environment.MachineName} User: {Environment.UserName} Session: {DscSync.Core.SessionInfo.CurrentSessionId}")
            .AppendLine($"RDP session: {WinNative.IsRemoteSession}")
            .AppendLine().AppendLine(diagnostics).AppendLine()
            .AppendLine(System.Text.Json.JsonSerializer.Serialize(safe, ConfigJson.Default.AppConfig));
        using (var w = new StreamWriter(zip.CreateEntry("environment.txt").Open())) w.Write(info.ToString());
        return zipPath;
    }
}
