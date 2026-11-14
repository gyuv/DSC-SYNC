using System.Collections.Concurrent;
using DscSync.Core.Audit;
using DscSync.Core.Protocol;
using DscSync.Core.Security;
using DscSync.Tunnel.Proxy;
using DscSync.Tunnel.Transports;

namespace DscSync.Pkcs11Bridge.Engine;

public sealed class LinkInfo
{
    public required string Transport { get; init; }
    public required string Peer { get; init; }
    public DateTime ConnectedUtc { get; init; } = DateTime.UtcNow;
}

public static class EventNames
{
    public const string TokenEvent = "TokenEvent";
}

/// <summary>Shared session loop: keeps every connector connected, re-trying with backoff.</summary>
public abstract class SyncEngineBase : IAsyncDisposable
{
    private readonly List<ITransportConnector> _connectors;
    private readonly List<Task> _loops = new();
    protected readonly CancellationTokenSource Cts = new();
    protected readonly ConcurrentDictionary<MuxConnection, LinkInfo> Links = new();

    protected SyncEngineBase(IEnumerable<ITransportConnector> connectors, string role, string pin)
    {
        _connectors = connectors.ToList();
        Role = role;
        Pin = pin;
    }

    public string Role { get; }
    protected string Pin { get; }
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(20);
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(3);

    public event Action<string>? Log;
    public event Action? LinksChanged;

    public IReadOnlyList<LinkInfo> ActiveLinks => Links.Values.OrderByDescending(l => l.ConnectedUtc).ToList();
    public bool IsLinked => !Links.IsEmpty;

    /// <summary>The most recently established link (RDP DVC preferred over TLS when both are up).</summary>
    public MuxConnection? PrimaryConnection =>
        Links.Where(kv => !kv.Key.IsClosed)
             .OrderByDescending(kv => kv.Value.Transport == TransportKinds.RdpDvc)
             .ThenByDescending(kv => kv.Value.ConnectedUtc)
             .Select(kv => kv.Key).FirstOrDefault();

    protected void Write(string message) => Log?.Invoke(message);

    protected void StartConnectorLoops()
    {
        foreach (var c in _connectors.Where(c => c.IsAvailable))
            _loops.Add(Task.Run(() => ConnectorLoopAsync(c)));
        if (_loops.Count == 0) Write("No transport is available (enable RDP DVC or configure the TLS tunnel).");
    }

    private async Task ConnectorLoopAsync(ITransportConnector connector)
    {
        int failures = 0;
        while (!Cts.IsCancellationRequested)
        {
            TransportConnection? conn = null;
            MuxConnection? mux = null;
            try
            {
                conn = await connector.ConnectAsync(Cts.Token).ConfigureAwait(false);
                mux = await SessionEstablisher.EstablishAsync(conn, Role, Pin, HandshakeTimeout, Cts.Token, ConfigureConnection).ConfigureAwait(false);
                failures = 0;
                Links[mux] = new LinkInfo { Transport = conn.Kind, Peer = mux.PeerName };
                Write($"Linked via {conn.Kind} to {mux.PeerName}");
                LinksChanged?.Invoke();
                await OnConnectedAsync(mux).ConfigureAwait(false);
                await mux.Completion.WaitAsync(Cts.Token).ConfigureAwait(false);
                Write($"{conn.Kind} link closed");
            }
            catch (OperationCanceledException) when (Cts.IsCancellationRequested) { break; }
            catch (PairingFailedException ex)
            {
                failures++;
                Write($"{connector.Kind}: pairing failed — {ex.Message}");
            }
            catch (Exception ex)
            {
                failures++;
                if (failures <= 3 || failures % 20 == 0) Write($"{connector.Kind}: {ex.Message}");
            }
            finally
            {
                if (mux is not null)
                {
                    Links.TryRemove(mux, out _);
                    await mux.DisposeAsync().ConfigureAwait(false);
                    OnDisconnected(mux);
                    LinksChanged?.Invoke();
                }
                else if (conn is not null)
                {
                    await conn.DisposeAsync().ConfigureAwait(false);
                }
            }
            try { await Task.Delay(failures == 0 ? TimeSpan.FromMilliseconds(500) : RetryDelay, Cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Install handlers before the read loop starts.</summary>
    protected abstract void ConfigureConnection(MuxConnection mux);
    protected abstract Task OnConnectedAsync(MuxConnection mux);
    protected virtual void OnDisconnected(MuxConnection mux) { }

    private int _disposed;

    public virtual async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Cts.Cancel();
        foreach (var l in Links.Keys) await l.DisposeAsync().ConfigureAwait(false);
        foreach (var c in _connectors) await c.DisposeAsync().ConfigureAwait(false);
        try { await Task.WhenAll(_loops).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } catch (Exception) { }
        Cts.Dispose();
    }
}

/// <summary>
/// Local PC (token source): answers PKCS#11 RPCs from the Remote VM, pushes TOKEN_INSERTED / TOKEN_REMOVED and
/// relays emSigner port streams to 127.0.0.1.
/// </summary>
public sealed class LocalAgent : SyncEngineBase
{
    private readonly TokenManager _tokens;
    private readonly LocalPortTarget _ports;
    private readonly bool _enablePortProxy;

    public LocalAgent(TokenManager tokens, IEnumerable<ITransportConnector> connectors, string pin, LocalPortTarget ports, bool enablePortProxy = true)
        : base(connectors, PairingHandshake.RoleLocal, pin)
    {
        _tokens = tokens;
        _ports = ports;
        _enablePortProxy = enablePortProxy;
        _tokens.TokenEvent += OnTokenEvent;
    }

    public TokenManager Tokens => _tokens;

    /// <summary>Optional audit trail on the Local PC (who on which server used this token).</summary>
    public AuditLog? Audit { get; set; }

    private void AuditUse(string op, ulong slot, string peer, string detail, bool ok)
    {
        if (Audit is null) return;
        var token = _tokens.State.Tokens.FirstOrDefault(t => t.SlotId == slot);
        var cert = token?.Certificates.FirstOrDefault();
        Audit.Write(new AuditEntry
        {
            Operation = op,
            TokenPc = Environment.MachineName,
            CertificateHolder = cert?.SubjectCommonName ?? "",
            TokenSerial = token?.SerialNumber ?? "",
            Issuer = cert?.IssuerCommonName ?? "",
            Application = "Remote: " + peer,
            Detail = detail,
            Success = ok,
        });
    }

    private static string PeerOf(CancellationToken _) => CurrentPeer.Value ?? "remote";
    private static readonly AsyncLocal<string?> CurrentPeer = new();

    public void Start() => StartConnectorLoops();

    protected override void ConfigureConnection(MuxConnection mux)
    {
        mux.RpcHandler = (m, b, ct) => { CurrentPeer.Value = mux.PeerName; return HandleRpcAsync(m, b, ct); };
        mux.StreamOpenHandler = _enablePortProxy ? _ports.OpenAsync : null;
    }

    protected override Task OnConnectedAsync(MuxConnection mux)
    {
        var snapshot = new TokenEventDto { Kind = TokenEventKind.Snapshot, State = _tokens.State };
        return mux.SendEventAsync(EventNames.TokenEvent, ProtocolJson.Serialize(snapshot, ProtocolJson.Default.TokenEventDto));
    }

    private void OnTokenEvent(TokenEventDto ev)
    {
        var body = ProtocolJson.Serialize(ev, ProtocolJson.Default.TokenEventDto);
        foreach (var mux in Links.Keys)
        {
            _ = mux.SendEventAsync(EventNames.TokenEvent, body).ContinueWith(
                t => Write("Failed to push token event: " + t.Exception?.GetBaseException().Message),
                TaskContinuationOptions.OnlyOnFaulted);
        }
    }

    private async Task<byte[]?> HandleRpcAsync(string method, byte[]? body, CancellationToken ct)
    {
        switch (method)
        {
            case RpcMethods.Ping:
                return ProtocolJson.Serialize(new PingDto { Ticks = DateTime.UtcNow.Ticks, Machine = Environment.MachineName, Role = Role }, ProtocolJson.Default.PingDto);
            case RpcMethods.GetTokenState:
                return ProtocolJson.Serialize(_tokens.State, ProtocolJson.Default.TokenStateDto);
            case RpcMethods.Login:
                {
                    var req = RpcBody.Deserialize(body, ProtocolJson.Default.LoginRequest);
                    try { await _tokens.LoginAsync(req.SlotId, req.Generation, req.Pin, ct).ConfigureAwait(false); }
                    catch (RpcException ex) { AuditUse(AuditOperations.Login, req.SlotId, PeerOf(ct), ex.Message, false); throw; }
                    AuditUse(AuditOperations.Login, req.SlotId, PeerOf(ct), "", true);
                    Write($"Token login OK (slot {req.SlotId:X})");
                    return null;
                }
            case RpcMethods.Logout:
                {
                    var req = RpcBody.Deserialize(body, ProtocolJson.Default.SlotRequest);
                    await _tokens.LogoutAsync(req.SlotId, ct).ConfigureAwait(false);
                    return null;
                }
            case RpcMethods.Sign:
                {
                    var req = RpcBody.Deserialize(body, ProtocolJson.Default.SignRequest);
                    byte[] sig;
                    try { sig = await _tokens.SignAsync(req, ct).ConfigureAwait(false); }
                    catch (RpcException ex) { AuditUse(AuditOperations.Sign, req.SlotId, PeerOf(ct), ex.Message, false); throw; }
                    AuditUse(AuditOperations.Sign, req.SlotId, PeerOf(ct), DscSync.Core.Pkcs11.CKM.Name(req.Mechanism), true);
                    Write($"Signed {req.Data.Length} bytes with {DscSync.Core.Pkcs11.CKM.Name(req.Mechanism)}");
                    return ProtocolJson.Serialize(new SignResponse { Signature = sig }, ProtocolJson.Default.SignResponse);
                }
            case RpcMethods.GetEmSignerCertificates:
                {
                    var list = new CertificateBlobList();
                    var seen = new HashSet<string>();
                    foreach (var port in _ports.AllowedPorts)
                    {
                        using var cert = await EmSignerCertificateProbe.ProbeAsync(_ports.MapPort(port), 2000, ct).ConfigureAwait(false);
                        if (cert is null || !seen.Add(cert.Thumbprint)) continue;
                        list.Items.Add(new CertificateBlob { Port = port, Der = cert.RawData, Subject = cert.Subject, Thumbprint = cert.Thumbprint });
                    }
                    return ProtocolJson.Serialize(list, ProtocolJson.Default.CertificateBlobList);
                }
            default:
                throw new RpcException(RpcErrors.UnknownMethod, $"Unknown method {method}");
        }
    }

    public override async ValueTask DisposeAsync()
    {
        _tokens.TokenEvent -= OnTokenEvent;
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

internal static class RpcBody
{
    public static T Deserialize<T>(byte[]? body, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
        => ProtocolJson.Deserialize<T>(body ?? throw new RpcException(DscSync.Core.Pkcs11.CKR.ARGUMENTS_BAD, "Missing body"), info);
}
