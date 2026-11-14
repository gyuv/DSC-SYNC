using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using DscSync.Core;
using DscSync.Core.Protocol;

namespace DscSync.Tunnel.Proxy;

/// <summary>Finds the Windows session that owns the client side of a loopback TCP connection.</summary>
public interface IConnectionOwnerResolver
{
    int? ResolveSession(IPEndPoint client, int serverPort);
}

/// <summary>Resolver used outside Windows (and in tests): everything belongs to the current session.</summary>
public sealed class CurrentSessionResolver : IConnectionOwnerResolver
{
    public int? ResolveSession(IPEndPoint client, int serverPort) => SessionInfo.CurrentSessionId;
}

/// <summary>Uses GetExtendedTcpTable to map the browser's socket → owning PID → RDS session id.</summary>
public sealed class WindowsTcpOwnerResolver : IConnectionOwnerResolver
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    public int? ResolveSession(IPEndPoint client, int serverPort)
    {
        if (!OperatingSystem.IsWindows()) return SessionInfo.CurrentSessionId;
        int pid = FindOwnerPid(client.Port, serverPort);
        return pid > 0 ? SessionInfo.ResolveSession(pid) : null;
    }

    private static int FindOwnerPid(int clientPort, int serverPort)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            size += 4096;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) continue;
                int count = Marshal.ReadInt32(buffer);
                const int rowSize = 24; // state, localAddr, localPort, remoteAddr, remotePort, pid
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = buffer + 4 + i * rowSize;
                    int localPort = Port(Marshal.ReadInt32(row, 8));
                    int remotePort = Port(Marshal.ReadInt32(row, 16));
                    if (localPort == clientPort && remotePort == serverPort) return Marshal.ReadInt32(row, 20);
                }
                return 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return 0;
    }

    private static int Port(int raw) => BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));
}

/// <summary>
/// Per-user endpoint. The machine-wide port broker hands it browser connections from this user's session through
/// a named pipe; it forwards them through this user's own tunnel to this user's Local PC / emSigner.
/// </summary>
public sealed class SessionProxyEndpoint : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly Func<int, CancellationToken, Task<Stream?>> _upstream;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<Guid, Stream> _active = new();
    private Task? _loop;

    public SessionProxyEndpoint(string pipeName, Func<int, CancellationToken, Task<Stream?>> upstream)
    {
        _pipeName = pipeName;
        _upstream = upstream;
    }

    public event Action<int>? ConnectionOpened;
    public event Action<string>? Log;
    public int ActiveConnections => _active.Count;
    public long TotalConnections;

    public void Start() => _loop = Task.Run(LoopAsync);

    private NamedPipeServerStream CreatePipe()
    {
        if (OperatingSystem.IsWindows())
        {
            // The broker may run in another user's session: allow authenticated users, verify the process below.
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
            return NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
        }
        return new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                var p = pipe;
                pipe = null;
                _ = Task.Run(() => ServeAsync(p));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                pipe?.Dispose();
                Log?.Invoke("Session proxy pipe: " + ex.Message);
                try { await Task.Delay(1000, _cts.Token).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe)
    {
        var id = Guid.NewGuid();
        try
        {
            if (!IsTrustedBroker(pipe)) { pipe.Dispose(); return; }
            var header = new byte[4];
            await pipe.ReadExactlyAsync(header, _cts.Token).ConfigureAwait(false);
            int port = BinaryPrimitives.ReadInt32BigEndian(header);
            Stream? upstream = null;
            try { upstream = await _upstream(port, _cts.Token).ConfigureAwait(false); }
            catch (Exception ex) { Log?.Invoke($"Port {port}: Local emSigner unreachable ({ex.Message})"); }
            await pipe.WriteAsync(new[] { upstream is null ? (byte)0 : (byte)1 }, _cts.Token).ConfigureAwait(false);
            await pipe.FlushAsync(_cts.Token).ConfigureAwait(false);
            if (upstream is null) return;
            Interlocked.Increment(ref TotalConnections);
            _active[id] = pipe;
            ConnectionOpened?.Invoke(port);
            await StreamPump.BridgeAsync(pipe, upstream, _cts.Token).ConfigureAwait(false);
        }
        catch (Exception) { }
        finally
        {
            _active.TryRemove(id, out _);
            pipe.Dispose();
        }
    }

    private static bool IsTrustedBroker(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows()) return true;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid)) return false;
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            using var self = Process.GetCurrentProcess();
            return string.Equals(proc.ProcessName, self.ProcessName, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception) { return false; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    /// <summary>Drops this user's live portal connections (stale keep-alive) after a token swap.</summary>
    public int ResetConnections()
    {
        int n = 0;
        foreach (var kv in _active)
            if (_active.TryRemove(kv.Key, out var s)) { s.Dispose(); n++; }
        return n;
    }

    private int _disposedFlag;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;
        _cts.Cancel();
        ResetConnections();
        if (_loop is not null) { try { await _loop.ConfigureAwait(false); } catch (Exception) { } }
        _cts.Dispose();
    }
}

/// <summary>
/// Machine-wide owner of the emSigner loopback ports. Every DSC-Sync instance on the server runs one; the first to
/// bind wins and the others keep retrying, so the ports survive any single user logging off. Each accepted browser
/// connection is routed to the session that owns the browser process.
/// </summary>
public sealed class PortBroker : IAsyncDisposable
{
    private readonly IConnectionOwnerResolver _resolver;
    private readonly Func<int, string> _pipeForSession;
    private readonly List<int> _ports;
    private readonly LoopbackPortProxy _proxy;
    private readonly CancellationTokenSource _cts = new();
    private Task? _election;

    public PortBroker(IEnumerable<int> ports, IConnectionOwnerResolver resolver, Func<int, string> pipeForSession)
    {
        _ports = ports.Distinct().ToList();
        _resolver = resolver;
        _pipeForSession = pipeForSession;
        _proxy = new LoopbackPortProxy(RouteAsync);
        _proxy.Log += m => Log?.Invoke(m);
    }

    public event Action<string>? Log;
    public TimeSpan ElectionInterval { get; set; } = TimeSpan.FromSeconds(5);
    public LoopbackPortProxy Proxy => _proxy;

    /// <summary>Ports this instance currently serves.</summary>
    public IReadOnlyList<PortStatus> Status => _proxy.Status;
    public bool OwnsAllPorts => _ports.All(p => _proxy.Status.Any(s => s.Port == p && s.State == PortState.Listening));

    public void Start()
    {
        TryBind();
        _election = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try { await Task.Delay(ElectionInterval, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                TryBind();
            }
        });
    }

    public IReadOnlyList<PortStatus> TryBind()
    {
        var missing = _ports.Where(p => !_proxy.Status.Any(s => s.Port == p && s.State == PortState.Listening)).ToList();
        if (missing.Count == 0) return Array.Empty<PortStatus>();
        var result = _proxy.Start(missing);
        foreach (var s in result.Where(s => s.State == PortState.Listening))
            Log?.Invoke($"Port router now serving 127.0.0.1:{s.Port} for all users on this server");
        return result;
    }

    private async Task<Stream?> RouteAsync(int port, IPEndPoint client, CancellationToken ct)
    {
        int session = _resolver.ResolveSession(client, port) ?? SessionInfo.CurrentSessionId;
        var pipe = new NamedPipeClientStream(".", _pipeForSession(session), PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(2000, ct).ConfigureAwait(false);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(header, port);
            await pipe.WriteAsync(header, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);
            var status = new byte[1];
            await pipe.ReadExactlyAsync(status, ct).ConfigureAwait(false);
            if (status[0] == 1) return pipe;
            Log?.Invoke($"Session {session}: DSC-Sync is running but its Local PC / emSigner is not connected");
        }
        catch (Exception)
        {
            Log?.Invoke($"Session {session}: user is not running DSC-Sync (port {port} request refused)");
        }
        await pipe.DisposeAsync().ConfigureAwait(false);
        return null;
    }

    private int _disposedFlag;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;
        _cts.Cancel();
        if (_election is not null) { try { await _election.ConfigureAwait(false); } catch (Exception) { } }
        await _proxy.DisposeAsync().ConfigureAwait(false);
        _cts.Dispose();
    }
}
