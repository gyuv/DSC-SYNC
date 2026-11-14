using DscSync.Core;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;
using DscSync.Core.Security;
using DscSync.Tunnel.Proxy;
using DscSync.Tunnel.Transports;

namespace DscSync.Pkcs11Bridge.Engine;

/// <summary>OS integration needed on the Remote VM (Windows implementation lives in the app).</summary>
public interface IRemotePlatform
{
    /// <summary>Stops any local emSigner / Java process or service that holds the emSigner ports.</summary>
    Task FreeEmSignerPortsAsync(IReadOnlyList<int> ports, Action<string> log, CancellationToken ct);
    /// <summary>Imports the Local PC's emSigner localhost certificate into the trusted root store.</summary>
    Task<bool> TrustCertificateAsync(CertificateBlob certificate, Action<string> log, CancellationToken ct);
}

public sealed class NullRemotePlatform : IRemotePlatform
{
    public Task FreeEmSignerPortsAsync(IReadOnlyList<int> ports, Action<string> log, CancellationToken ct) => Task.CompletedTask;
    public Task<bool> TrustCertificateAsync(CertificateBlob certificate, Action<string> log, CancellationToken ct) => Task.FromResult(false);
}

public sealed class RemoteHostOptions
{
    public List<int> EmSignerPorts { get; set; } = new(DscConstants.EmSignerPorts);
    public bool EnablePortProxy { get; set; } = true;
    public bool StopLocalEmSigner { get; set; } = true;
    public bool SyncEmSignerCertificate { get; set; } = true;
    public string P11PipeName { get; set; } = DscConstants.P11PipeName;
    public bool EnableP11Pipe { get; set; } = true;
}

/// <summary>
/// Remote VM (target): exposes the Local PC's token to DSC-Sync-P11.dll via a named pipe, proxies the emSigner
/// loopback ports, and keeps a cached mirror of the Local token state updated by pushed events.
/// </summary>
public sealed class RemoteHost : SyncEngineBase, ITokenClient
{
    private readonly RemoteHostOptions _options;
    private readonly IRemotePlatform _platform;
    private readonly LoopbackPortProxy _proxy;
    private P11PipeServer? _pipe;
    private readonly object _stateLock = new();
    private TokenStateDto _state = new() { Generation = 1 };
    private TaskCompletionSource _stateChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private List<CertificateBlob> _trusted = new();

    public RemoteHost(IEnumerable<ITransportConnector> connectors, string pin, RemoteHostOptions options, IRemotePlatform platform)
        : base(connectors, PairingHandshake.RoleRemote, pin)
    {
        _options = options;
        _platform = platform;
        _proxy = new LoopbackPortProxy(() => PrimaryConnection);
        _proxy.Log += Write;
    }

    public event Action<TokenEventDto>? TokenEvent;

    public TokenStateDto State { get { lock (_stateLock) return _state; } }
    public bool IsConnected => PrimaryConnection is not null;
    public LoopbackPortProxy Proxy => _proxy;
    public IReadOnlyList<CertificateBlob> TrustedCertificates { get { lock (_stateLock) return _trusted.ToList(); } }
    public IReadOnlyList<PortStatus> PortStatus => _proxy.Status;
    public int P11Clients => _pipe?.ConnectedClients ?? 0;

    public async Task StartAsync()
    {
        if (_options.EnablePortProxy)
        {
            if (_options.StopLocalEmSigner)
                await _platform.FreeEmSignerPortsAsync(_options.EmSignerPorts, Write, Cts.Token).ConfigureAwait(false);
            foreach (var s in _proxy.Start(_options.EmSignerPorts).Where(s => s.State != PortState.Listening))
                Write($"Port {s.Port}: {s.State} — {s.Detail}");
        }
        if (_options.EnableP11Pipe)
        {
            _pipe = new P11PipeServer(HandlePipeRpcAsync, _options.P11PipeName);
            _pipe.Start();
        }
        StartConnectorLoops();
    }

    /// <summary>Retries binding ports that were busy (e.g. after the auto-fix stopped emSigner).</summary>
    public async Task RebindPortsAsync()
    {
        if (_options.StopLocalEmSigner)
            await _platform.FreeEmSignerPortsAsync(_options.EmSignerPorts, Write, Cts.Token).ConfigureAwait(false);
        await _proxy.StopAsync().ConfigureAwait(false);
        foreach (var s in _proxy.Start(_options.EmSignerPorts).Where(s => s.State != PortState.Listening))
            Write($"Port {s.Port}: {s.State} — {s.Detail}");
    }

    protected override void ConfigureConnection(MuxConnection mux)
    {
        mux.RpcHandler = (method, _, _) => method == RpcMethods.Ping
            ? Task.FromResult<byte[]?>(ProtocolJson.Serialize(new PingDto { Ticks = DateTime.UtcNow.Ticks, Machine = Environment.MachineName, Role = Role }, ProtocolJson.Default.PingDto))
            : throw new RpcException(RpcErrors.UnknownMethod, "Remote host does not serve " + method);
        mux.EventReceived += (name, body) =>
        {
            if (name != EventNames.TokenEvent || body is null) return;
            var ev = ProtocolJson.Deserialize(body, ProtocolJson.Default.TokenEventDto);
            ApplyTokenEvent(ev);
        };
    }

    protected override async Task OnConnectedAsync(MuxConnection mux)
    {
        try
        {
            var body = await mux.CallAsync(RpcMethods.GetTokenState, null, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            if (body is not null)
                ApplyTokenEvent(new TokenEventDto { Kind = TokenEventKind.Snapshot, State = ProtocolJson.Deserialize(body, ProtocolJson.Default.TokenStateDto) });
        }
        catch (RpcException ex) { Write("Initial token state failed: " + ex.Message); }

        if (_options.SyncEmSignerCertificate)
            _ = Task.Run(() => SyncCertificatesAsync(mux));
    }

    public async Task<int> SyncCertificatesAsync(MuxConnection? mux = null)
    {
        mux ??= PrimaryConnection;
        if (mux is null) return 0;
        try
        {
            var body = await mux.CallAsync(RpcMethods.GetEmSignerCertificates, null, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
            if (body is null) return 0;
            var list = ProtocolJson.Deserialize(body, ProtocolJson.Default.CertificateBlobList);
            if (list.Items.Count == 0) Write("Local emSigner is not running (no localhost certificate to sync yet)");
            int trusted = 0;
            foreach (var cert in list.Items)
                if (await _platform.TrustCertificateAsync(cert, Write, Cts.Token).ConfigureAwait(false)) trusted++;
            lock (_stateLock) _trusted = list.Items;
            return trusted;
        }
        catch (Exception ex)
        {
            Write("emSigner certificate sync failed: " + ex.Message);
            return 0;
        }
    }

    protected override void OnDisconnected(MuxConnection mux)
    {
        if (PrimaryConnection is null)
        {
            // Link lost: the token is "unplugged" from the VM's point of view.
            ApplyTokenEvent(new TokenEventDto
            {
                Kind = TokenEventKind.TokenRemoved,
                State = new TokenStateDto { TimestampUtc = DateTime.UtcNow },
                RemovedSerials = State.Tokens.Select(t => t.SerialNumber).ToList(),
            });
        }
    }

    private void ApplyTokenEvent(TokenEventDto ev)
    {
        TaskCompletionSource toSignal;
        lock (_stateLock)
        {
            // Remote keeps its own monotonically increasing generation so that disconnects also count as changes.
            var mirrored = new TokenStateDto { Generation = _state.Generation + 1, TimestampUtc = DateTime.UtcNow, Tokens = ev.State.Tokens };
            bool changed = Fingerprint(mirrored) != Fingerprint(_state);
            if (!changed && ev.Kind == TokenEventKind.Snapshot) return;
            _state = mirrored;
            ev = new TokenEventDto { Kind = ev.Kind, State = mirrored, AddedSerials = ev.AddedSerials, RemovedSerials = ev.RemovedSerials };
            toSignal = _stateChanged;
            _stateChanged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        if (ev.Kind is TokenEventKind.TokenInserted or TokenEventKind.TokenRemoved or TokenEventKind.TokenChanged)
        {
            int dropped = _proxy.ResetConnections();
            if (dropped > 0) Write($"Token changed: dropped {dropped} stale emSigner connection(s)");
        }
        toSignal.TrySetResult();
        try { TokenEvent?.Invoke(ev); } catch (Exception ex) { Write("Token event handler failed: " + ex.Message); }
    }

    private static string Fingerprint(TokenStateDto s) =>
        string.Join("|", s.Tokens.Select(t => $"{t.SlotId}:{t.SerialNumber}:{string.Join(",", t.Certificates.Select(c => c.Thumbprint))}"));

    private async Task<byte[]?> HandlePipeRpcAsync(string method, byte[]? body, CancellationToken ct)
    {
        switch (method)
        {
            case RpcMethods.GetTokenState:
                return ProtocolJson.Serialize(State, ProtocolJson.Default.TokenStateDto);
            case RpcMethods.Status:
                {
                    var link = ActiveLinks.FirstOrDefault();
                    return ProtocolJson.Serialize(new LinkStatusDto { Connected = link is not null, Transport = link?.Transport ?? "", Peer = link?.Peer ?? "" }, ProtocolJson.Default.LinkStatusDto);
                }
            case RpcMethods.WaitEvent:
                {
                    var req = RpcBody.Deserialize(body, ProtocolJson.Default.WaitEventRequest);
                    Task wait;
                    lock (_stateLock)
                    {
                        if (_state.Generation != req.KnownGeneration) return null;
                        wait = _stateChanged.Task;
                    }
                    try { await wait.WaitAsync(TimeSpan.FromMilliseconds(Math.Clamp(req.TimeoutMs, 100, 30_000)), ct).ConfigureAwait(false); }
                    catch (TimeoutException) { }
                    return null;
                }
            case RpcMethods.Login:
            case RpcMethods.Logout:
            case RpcMethods.Sign:
            case RpcMethods.Ping:
                {
                    var mux = PrimaryConnection ?? throw new RpcException(CKR.DEVICE_REMOVED, "Local PC with the DSC token is not connected");
                    return await mux.CallAsync(method, body, TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
                }
            default:
                throw new RpcException(RpcErrors.UnknownMethod, $"Unknown method {method}");
        }
    }

    // ITokenClient (used by the built-in PDF signer and diagnostics on the Remote VM)
    public async Task LoginAsync(ulong slotId, long generation, string pin, CancellationToken ct = default)
    {
        var mux = PrimaryConnection ?? throw new RpcException(CKR.DEVICE_REMOVED, "Local PC is not connected");
        await mux.CallAsync(RpcMethods.Login, ProtocolJson.Serialize(new LoginRequest { SlotId = slotId, Generation = generation, Pin = pin }, ProtocolJson.Default.LoginRequest), TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
    }

    public async Task<byte[]> SignAsync(SignRequest request, CancellationToken ct = default)
    {
        var mux = PrimaryConnection ?? throw new RpcException(CKR.DEVICE_REMOVED, "Local PC is not connected");
        var body = await mux.CallAsync(RpcMethods.Sign, ProtocolJson.Serialize(request, ProtocolJson.Default.SignRequest), TimeSpan.FromMinutes(2), ct).ConfigureAwait(false)
                   ?? throw new RpcException(CKR.FUNCTION_FAILED, "Empty signature");
        return ProtocolJson.Deserialize(body, ProtocolJson.Default.SignResponse).Signature;
    }

    public async Task<TimeSpan> PingAsync(CancellationToken ct = default)
    {
        var mux = PrimaryConnection ?? throw new RpcException(RpcErrors.NotConnected, "Local PC is not connected");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await mux.CallAsync(RpcMethods.Ping, null, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        return sw.Elapsed;
    }

    private int _hostDisposed;

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _hostDisposed, 1) != 0) return;
        if (_pipe is not null) await _pipe.DisposeAsync().ConfigureAwait(false);
        await _proxy.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
