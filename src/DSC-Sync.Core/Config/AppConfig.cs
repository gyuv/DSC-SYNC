using System.Text.Json;
using System.Text.Json.Serialization;

namespace DscSync.Core.Config;

public enum SyncMode { Local = 0, Remote = 1 }

public enum TransportPreference { Auto = 0, RdpDvcOnly = 1, TcpOnly = 2 }

/// <summary>Persisted in %AppData%\DSC-Sync\config.json.</summary>
public sealed class AppConfig
{
    public SyncMode Mode { get; set; } = SyncMode.Local;
    public TransportPreference Transport { get; set; } = TransportPreference.Auto;

    /// <summary>Local mode: host name / IP of the Remote VM running DSC-Sync in Remote mode (TCP fallback).</summary>
    public string RemoteHost { get; set; } = "";
    /// <summary>Remote mode: listen address for the TCP fallback ("0.0.0.0" = all interfaces).</summary>
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int TunnelPort { get; set; } = DscConstants.DefaultTunnelPort;
    public bool EnableTcpTunnel { get; set; } = true;

    /// <summary>Shared pairing PIN (must match on both machines).</summary>
    public string PairingPin { get; set; } = "";

    public List<int> EmSignerPorts { get; set; } = new(DscConstants.EmSignerPorts);
    public bool EnablePortProxy { get; set; } = true;
    public bool StopRemoteEmSigner { get; set; } = true;
    public bool SyncEmSignerCertificate { get; set; } = true;

    /// <summary>Optional explicit vendor PKCS#11 library paths; auto-discovery is used when empty.</summary>
    public List<string> VendorLibraries { get; set; } = new();

    public bool StartMinimized { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool UseSimulatedToken { get; set; }

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), DscConstants.AppFolderName);

    public static string DefaultPath => Path.Combine(DefaultDirectory, "config.json");

    public static AppConfig Load(string? path = null)
    {
        path ??= DefaultPath;
        try
        {
            if (File.Exists(path))
            {
                var cfg = JsonSerializer.Deserialize(File.ReadAllText(path), ConfigJson.Default.AppConfig);
                if (cfg is not null)
                {
                    if (cfg.EmSignerPorts.Count == 0) cfg.EmSignerPorts = new(DscConstants.EmSignerPorts);
                    return cfg;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            var backup = path + ".corrupt";
            try { File.Copy(path, backup, overwrite: true); } catch (IOException) { }
        }
        return new AppConfig();
    }

    public void Save(string? path = null)
    {
        path ??= DefaultPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, ConfigJson.Default.AppConfig));
        File.Move(tmp, path, overwrite: true);
    }

    public AppConfig Clone() =>
        JsonSerializer.Deserialize(JsonSerializer.Serialize(this, ConfigJson.Default.AppConfig), ConfigJson.Default.AppConfig)!;
}

[JsonSourceGenerationOptions(WriteIndented = true, UseStringEnumConverter = true)]
[JsonSerializable(typeof(AppConfig))]
public sealed partial class ConfigJson : JsonSerializerContext { }
