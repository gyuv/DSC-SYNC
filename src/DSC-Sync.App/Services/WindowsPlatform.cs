using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using DscSync.Core;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge.Engine;

namespace DscSync.App.Services;

public static class WinNative
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    private const int TCP_TABLE_OWNER_PID_LISTENER = 3;

    /// <summary>PIDs listening on each TCP port (IPv4).</summary>
    public static Dictionary<int, int> ListenerOwners()
    {
        var result = new Dictionary<int, int>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, TCP_TABLE_OWNER_PID_LISTENER, 0);
        size += 8192;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, 2, TCP_TABLE_OWNER_PID_LISTENER, 0) != 0) return result;
            int count = Marshal.ReadInt32(buffer);
            for (int i = 0; i < count; i++)
            {
                IntPtr row = buffer + 4 + i * 24;
                int port = BinaryPrimitives.ReverseEndianness((ushort)(Marshal.ReadInt32(row, 8) & 0xFFFF));
                result.TryAdd(port, Marshal.ReadInt32(row, 20));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    public static string ProcessName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch (Exception) { return $"PID {pid}"; }
    }

    public static string? PipeClientApp(NamedPipeServerStream pipe) =>
        GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid) ? ProcessName((int)pid) : null;

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool IsRemoteSession => System.Windows.Forms.SystemInformation.TerminalServerSession;
}

/// <summary>Remote-VM integration: frees emSigner ports in this user's session and trusts the Local emSigner cert.</summary>
public sealed class WindowsRemotePlatform : IRemotePlatform
{
    public Task FreeEmSignerPortsAsync(IReadOnlyList<int> ports, Action<string> log, CancellationToken ct) => Task.Run(() =>
    {
        int mySession = SessionInfo.CurrentSessionId;
        int myPid = Environment.ProcessId;
        var owners = WinNative.ListenerOwners();
        var victims = new HashSet<int>();

        foreach (var port in ports)
        {
            if (!owners.TryGetValue(port, out var pid) || pid == myPid || pid <= 4) continue;
            var name = WinNative.ProcessName(pid);
            if (name.StartsWith("DSC-Sync", StringComparison.OrdinalIgnoreCase)) continue; // router of another session
            if (SessionInfo.ResolveSession(pid) == mySession || LooksLikeEmSigner(pid)) victims.Add(pid);
            else log($"Port {port} is held by {name} in another session; ask an administrator to stop it");
        }
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.SessionId == mySession && p.ProcessName.Contains("emsigner", StringComparison.OrdinalIgnoreCase)) victims.Add(p.Id);
            }
            catch (Exception) { }
            finally { p.Dispose(); }
        }
        foreach (var pid in victims)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                log($"Stopping conflicting {p.ProcessName}.exe (PID {pid}) that blocks emSigner ports on this VM");
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
            }
            catch (Exception ex) { log($"Could not stop PID {pid}: {ex.Message}"); }
        }

        // An emSigner Windows service on the server blocks every user; stop it when we are allowed to.
        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                using (svc)
                {
                    if (!(svc.ServiceName.Contains("emsigner", StringComparison.OrdinalIgnoreCase) ||
                          svc.DisplayName.Contains("emsigner", StringComparison.OrdinalIgnoreCase))) continue;
                    if (svc.Status != ServiceControllerStatus.Running) continue;
                    try
                    {
                        svc.Stop();
                        svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                        log($"Stopped emSigner service '{svc.DisplayName}' on this server");
                    }
                    catch (Exception)
                    {
                        log($"emSigner service '{svc.DisplayName}' is running; an administrator should disable it on the server");
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private static bool LooksLikeEmSigner(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT Name, CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject o in searcher.Get())
            {
                var cmd = (o["CommandLine"] as string ?? "") + " " + (o["Name"] as string ?? "");
                if (cmd.Contains("emsigner", StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        catch (Exception) { }
        return false;
    }

    public Task<bool> TrustCertificateAsync(CertificateBlob certificate, Action<string> log, CancellationToken ct) =>
        Task.FromResult(CertificateTrust.TrustRoot(certificate.Der, log));
}

public static class CertificateTrust
{
    /// <summary>True when the certificate is in the machine or user Root store.</summary>
    public static bool IsTrusted(string thumbprint) =>
        Contains(StoreLocation.LocalMachine, thumbprint) || Contains(StoreLocation.CurrentUser, thumbprint);

    private static bool Contains(StoreLocation location, string thumbprint)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
        }
        catch (Exception) { return false; }
    }

    /// <summary>
    /// Imports into LocalMachine\Root when running as admin (silent, all users), otherwise into CurrentUser\Root
    /// (Windows asks the user to confirm once). Chrome and Edge use these stores.
    /// </summary>
    public static bool TrustRoot(byte[] der, Action<string> log)
    {
        using var cert = new X509Certificate2(der);
        if (IsTrusted(cert.Thumbprint)) return true;
        foreach (var location in WinNative.IsAdministrator()
                     ? new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser }
                     : new[] { StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                log($"Trusted emSigner localhost certificate '{cert.GetNameInfo(X509NameType.SimpleName, false)}' in {location}\\Root");
                return true;
            }
            catch (Exception ex)
            {
                log($"Could not add certificate to {location}\\Root: {ex.Message}");
            }
        }
        return false;
    }
}
