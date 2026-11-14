namespace DscSync.Core;

/// <summary>Well-known constants shared by every DSC-Sync component.</summary>
public static class DscConstants
{
    public const int ProtocolVersion = 1;

    /// <summary>Loopback ports used by emSigner (GST, MCA V3, Income Tax, TRACES) across v2.x and v3.3.</summary>
    public static readonly int[] EmSignerPorts = { 1585, 8080, 2015, 2095, 2568, 2868, 4587, 1645 };

    public const int DefaultTunnelPort = 49155;

    /// <summary>Dynamic virtual channel name (max 7 chars + NUL for static, DVC allows longer but keep it short).</summary>
    public const string DvcChannelName = "DSCSYNC";

    /// <summary>Pipe used by the mstsc RDP client plug-in to hand the DVC to the local DSC-Sync app.</summary>
    public const string DvcPluginPipeName = "DSC-Sync-DVC";

    /// <summary>Pipe used by DSC-Sync-P11.dll (loaded in Acrobat / browsers on the remote VM) to reach DSC-Sync.exe.</summary>
    public const string P11PipeName = "DSC-Sync-P11";

    public const string AppFolderName = "DSC-Sync";
}
