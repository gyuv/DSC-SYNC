using System.Runtime.InteropServices;

namespace DscSync.Core;

/// <summary>
/// Windows Server 2019 RDS hosts many users at once. Named pipes and 127.0.0.1 ports are machine-wide, so every
/// per-user endpoint is scoped by the Terminal Services session id.
/// </summary>
public static partial class SessionInfo
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);

    public static int CurrentSessionId { get; } = ResolveSession(Environment.ProcessId) ?? 0;

    public static int? ResolveSession(int processId)
    {
        if (!OperatingSystem.IsWindows()) return null;
        return ProcessIdToSessionId((uint)processId, out var sid) ? (int)sid : null;
    }

    public static string UserName => Environment.UserDomainName is { Length: > 0 } d && !d.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)
        ? $"{d}\\{Environment.UserName}" : Environment.UserName;

    public static string P11Pipe(int? session = null) => $"{DscConstants.P11PipeName}-{session ?? CurrentSessionId}";
    public static string ProxyPipe(int session) => $"DSC-Sync-Proxy-{session}";
    public const string BrokerPipe = "DSC-Sync-PortBroker";
}
