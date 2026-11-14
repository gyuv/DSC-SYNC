using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using DscSync.Core.Protocol;

namespace DscSync.Tunnel.Proxy;

public enum PortState { Stopped, Listening, InUse, Error }

public sealed class PortStatus
{
    public int Port { get; init; }
    public PortState State { get; set; }
    public string Detail { get; set; } = "";
    public int ActiveConnections { get; set; }
    public long TotalConnections { get; set; }
}

/// <summary>
/// Remote-VM side of Channel A. Binds 127.0.0.1:{emSigner ports} and forwards every accepted TCP connection as a
/// raw byte stream through the tunnel to 127.0.0.1:{same port} on the Local PC, where the real emSigner runs.
/// Because bytes are relayed untouched, TLS (incl. SNI), HTTP keep-alive and WebSocket upgrades work end-to-end.
/// </summary>
public sealed class LoopbackPortProxy : IAsyncDisposable
{
    private readonly Func<int, IPEndPoint, CancellationToken, Task<Stream?>> _upstream;
    private readonly ConcurrentDictionary<int, Listener> _listeners = new();
    private readonly CancellationTokenSource _cts = new();

    /// <summary>Proxy that opens upstream streams through a callback (port, browser endpoint).</summary>
    public LoopbackPortProxy(Func<int, IPEndPoint, CancellationToken, Task<Stream?>> upstream) => _upstream = upstream;

    /// <summary>Single-user proxy forwarding straight into a tunnel connection.</summary>
    public LoopbackPortProxy(Func<MuxConnection?> connection)
        : this(async (port, _, ct) =>
        {
            var mux = connection();
            if (mux is null || mux.IsClosed) return null;
            return await mux.OpenStreamAsync(port, ct).ConfigureAwait(false);
        })
    {
    }

    public event Action<string>? Log;

    private sealed class Listener
    {
        public required TcpListener Socket;
        public required PortStatus Status;
        public readonly ConcurrentDictionary<Guid, TcpClient> Clients = new();
    }

    public IReadOnlyList<PortStatus> Status =>
        _listeners.Values.Select(l => { l.Status.ActiveConnections = l.Clients.Count; return l.Status; }).OrderBy(s => s.Port).ToList();

    /// <summary>Starts listening on each port. Returns the status per port (InUse when another process holds it).</summary>
    public IReadOnlyList<PortStatus> Start(IEnumerable<int> ports)
    {
        var result = new List<PortStatus>();
        foreach (var port in ports.Distinct())
        {
            if (_listeners.TryGetValue(port, out var existing)) { result.Add(existing.Status); continue; }
            var status = new PortStatus { Port = port };
            try
            {
                var socket = new TcpListener(IPAddress.Loopback, port);
                if (OperatingSystem.IsWindows()) socket.Server.ExclusiveAddressUse = true; // no port hijacking by other users
                socket.Start();
                var l = new Listener { Socket = socket, Status = status };
                status.State = PortState.Listening;
                status.Detail = "Forwarding to Local PC";
                _listeners[port] = l;
                _ = Task.Run(() => AcceptLoopAsync(l));
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied)
            {
                status.State = PortState.InUse;
                status.Detail = "Port held by another process (emSigner / Java / web server?)";
            }
            catch (SocketException ex)
            {
                status.State = PortState.Error;
                status.Detail = ex.Message;
            }
            result.Add(status);
        }
        return result;
    }

    public int BoundPort(int port) => _listeners.TryGetValue(port, out var l) ? ((IPEndPoint)l.Socket.LocalEndpoint).Port : 0;

    private async Task AcceptLoopAsync(Listener l)
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await l.Socket.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false); }
            catch (Exception) { break; }
            client.NoDelay = true;
            l.Status.TotalConnections++;
            _ = Task.Run(() => HandleClientAsync(l, client));
        }
    }

    private async Task HandleClientAsync(Listener l, TcpClient client)
    {
        var id = Guid.NewGuid();
        l.Clients[id] = client;
        try
        {
            Stream? remote;
            try
            {
                remote = await _upstream(l.Status.Port, (IPEndPoint)client.Client.RemoteEndPoint!, _cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Port {l.Status.Port}: Local emSigner unreachable ({ex.Message})");
                return;
            }
            if (remote is null)
            {
                Log?.Invoke($"Port {l.Status.Port}: browser connected but the Local PC is not linked; connection refused");
                return;
            }
            await StreamPump.BridgeAsync(client.GetStream(), remote, _cts.Token).ConfigureAwait(false);
        }
        finally
        {
            l.Clients.TryRemove(id, out _);
            client.Dispose();
        }
    }

    /// <summary>Drops every live browser connection (stale keep-alive / WebSocket) e.g. after a token swap.</summary>
    public int ResetConnections()
    {
        int n = 0;
        foreach (var l in _listeners.Values)
            foreach (var kv in l.Clients)
                if (l.Clients.TryRemove(kv.Key, out var c)) { c.Dispose(); n++; }
        return n;
    }

    public async Task StopAsync()
    {
        foreach (var l in _listeners.Values)
        {
            l.Socket.Stop();
            foreach (var c in l.Clients.Values) c.Dispose();
            l.Status.State = PortState.Stopped;
        }
        _listeners.Clear();
        await Task.CompletedTask;
    }

    private int _disposedFlag;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;
        _cts.Cancel();
        await StopAsync().ConfigureAwait(false);
        _cts.Dispose();
    }
}

/// <summary>Local-PC side of Channel A: connects tunnel streams to 127.0.0.1:{allowed port} (emSigner).</summary>
public sealed class LocalPortTarget
{
    private readonly HashSet<int> _allowed;

    public LocalPortTarget(IEnumerable<int> allowedPorts) => _allowed = new HashSet<int>(allowedPorts);

    public IReadOnlyCollection<int> AllowedPorts => _allowed;

    /// <summary>Port remapping used by tests; production maps every port to itself.</summary>
    public Func<int, int> MapPort { get; set; } = p => p;

    public async Task<Stream?> OpenAsync(int port, CancellationToken ct)
    {
        if (!_allowed.Contains(port)) return null; // never let the remote reach arbitrary local services
        var client = new TcpClient { NoDelay = true };
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(IPAddress.Loopback, MapPort(port), cts.Token).ConfigureAwait(false);
            return new OwningNetworkStream(client);
        }
        catch (Exception)
        {
            client.Dispose();
            return null;
        }
    }

    private sealed class OwningNetworkStream : NetworkStream
    {
        private readonly TcpClient _client;
        public OwningNetworkStream(TcpClient c) : base(c.Client, ownsSocket: true) => _client = c;
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) _client.Dispose();
        }
    }
}

public static class LocalPortScanner
{
    /// <summary>True when something accepts TCP connections on 127.0.0.1:port.</summary>
    public static async Task<bool> IsListeningAsync(int port, int timeoutMs = 400)
    {
        using var c = new TcpClient();
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            await c.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception) { return false; }
    }
}

/// <summary>
/// Captures the certificate emSigner presents on https://127.0.0.1:port so the Remote VM can trust exactly that
/// certificate (prevents ERR_CERT_AUTHORITY_INVALID once traffic is proxied).
/// </summary>
public static class EmSignerCertificateProbe
{
    public static async Task<X509Certificate2?> ProbeAsync(int port, int timeoutMs = 3000, CancellationToken ct = default)
    {
        using var client = new TcpClient();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
            X509Certificate2? captured = null;
            X509Certificate2? root = null;
            await using var ssl = new SslStream(client.GetStream(), false, (_, cert, chain, _) =>
            {
                if (cert is not null) captured = new X509Certificate2(cert);
                // Prefer the self-signed root of the presented chain when emSigner uses its own mini-CA.
                if (chain?.ChainElements.Count > 1)
                {
                    var last = chain.ChainElements[^1].Certificate;
                    if (last.SubjectName.RawData.AsSpan().SequenceEqual(last.IssuerName.RawData)) root = new X509Certificate2(last);
                }
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "127.0.0.1",
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token).ConfigureAwait(false);
            return root ?? captured;
        }
        catch (Exception)
        {
            return null; // port not TLS or emSigner not running
        }
    }
}
