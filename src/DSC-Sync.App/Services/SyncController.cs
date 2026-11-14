using System.Net;
using System.Net.Sockets;
using DscSync.Core;
using DscSync.Core.Audit;
using DscSync.Core.Config;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge;
using DscSync.Pkcs11Bridge.Backends;
using DscSync.Pkcs11Bridge.Engine;
using DscSync.Pkcs11Bridge.Simulation;
using DscSync.Tunnel.Dvc;
using DscSync.Tunnel.Proxy;
using DscSync.Tunnel.Transports;

namespace DscSync.App.Services;

/// <summary>Builds and owns the Local agent or Remote host according to the configuration.</summary>
public sealed class SyncController : IAsyncDisposable
{
    /// <summary>Used when no PIN is configured. Only the RDP channel is enabled then: it never leaves the user's
    /// own encrypted RDP session, so zero-configuration is safe. The TCP tunnel always requires a real PIN.</summary>
    private const string RdpOnlyDefaultPin = "DSC-Sync/RDP-session-bound";

    private readonly FileLog _fileLog;
    private LocalAgent? _local;
    private RemoteHost? _remote;
    private TokenManager? _tokens;
    private DeviceWatcher? _watcher;
    private Pkcs11TokenBackend? _hwBackend;

    public SyncController(FileLog fileLog, AuditLog audit)
    {
        _fileLog = fileLog;
        Audit = audit;
    }

    public AuditLog Audit { get; }
    public AppConfig Config { get; private set; } = new();
    public SyncMode Mode => Config.Mode;
    public LocalAgent? Local => _local;
    public RemoteHost? Remote => _remote;
    public TokenManager? Tokens => _tokens;
    public int TlsPort { get; private set; }
    public IReadOnlyList<string> LoadedLibraries => _hwBackend?.LoadedLibraries ?? Array.Empty<string>();

    public ITokenClient? Client => (ITokenClient?)_tokens ?? _remote;
    public TokenStateDto State => Client?.State ?? new TokenStateDto();
    public SyncEngineBase? Engine => (SyncEngineBase?)_local ?? _remote;
    public bool IsLinked => Engine?.IsLinked ?? false;
    public LinkInfo? Link => Engine?.ActiveLinks.FirstOrDefault();

    public event Action<string>? Log;
    public event Action? Changed;
    public event Action<TokenEventDto>? TokenEvent;

    private void Write(string m)
    {
        _fileLog.Write(m);
        Log?.Invoke(m);
    }

    public async Task StartAsync(AppConfig config)
    {
        await StopAsync();
        Config = config.Clone();
        bool hasPin = !string.IsNullOrWhiteSpace(Config.PairingPin);
        string pin = hasPin ? Config.PairingPin : RdpOnlyDefaultPin;
        bool useDvc = Config.Transport != TransportPreference.TcpOnly;
        bool useTcp = Config.Transport != TransportPreference.RdpDvcOnly && Config.EnableTcpTunnel;
        if (useTcp && !hasPin)
        {
            useTcp = false;
            Write("TLS tunnel disabled: set a pairing PIN (Settings) to use it. RDP channel works without a PIN.");
        }

        if (Config.Mode == SyncMode.Local) StartLocal(pin, useDvc, useTcp);
        else await StartRemoteAsync(pin, useDvc, useTcp);
        Write($"DSC-Sync started in {Config.Mode} mode (session {SessionInfo.CurrentSessionId}, user {SessionInfo.UserName})");
        Changed?.Invoke();
    }

    private void StartLocal(string pin, bool useDvc, bool useTcp)
    {
        ITokenBackend backend;
        if (Config.UseSimulatedToken)
        {
            var mock = new MockTokenBackend();
            mock.Insert(MockToken.Create("DEMO SIGNATORY", "SIM-0001"));
            backend = mock;
        }
        else
        {
            _hwBackend = new Pkcs11TokenBackend(() => VendorLibraryLocator.Discover(Config.VendorLibraries));
            _hwBackend.Log += Write;
            backend = _hwBackend;
        }
        _tokens = new TokenManager(backend);
        _tokens.Log += Write;
        _tokens.TokenEvent += e => { TokenEvent?.Invoke(e); Changed?.Invoke(); };
        _tokens.Rescan(reload: true);
        _tokens.StartPolling(TimeSpan.FromSeconds(2));

        try
        {
            _watcher = new DeviceWatcher();
            _watcher.DeviceChanged += arrival => _tokens.RequestRescan(reload: arrival);
        }
        catch (Exception ex) { Write("Device notifications unavailable, polling only: " + ex.Message); }

        var connectors = new List<ITransportConnector>();
        if (useDvc)
        {
            Installer.RegisterRdpPlugin(Write);
            connectors.Add(new DvcPluginPipeConnector());
        }
        if (useTcp && !string.IsNullOrWhiteSpace(Config.RemoteHost))
            connectors.Add(new TlsTunnelClient(Config.RemoteHost.Trim(), Config.TunnelPort));

        _local = new LocalAgent(_tokens, connectors, pin, new LocalPortTarget(Config.EmSignerPorts), Config.EnablePortProxy) { Audit = Audit };
        _local.Log += Write;
        _local.LinksChanged += () => Changed?.Invoke();
        _local.Start();
    }

    private async Task StartRemoteAsync(string pin, bool useDvc, bool useTcp)
    {
        var connectors = new List<ITransportConnector>();
        if (useDvc) connectors.Add(new DvcServerConnector());
        if (useTcp)
        {
            var server = CreateTlsServer();
            if (server is not null) connectors.Add(server);
        }
        _remote = new RemoteHost(connectors, pin, new RemoteHostOptions
        {
            EmSignerPorts = Config.EmSignerPorts,
            EnablePortProxy = Config.EnablePortProxy,
            StopLocalEmSigner = Config.StopRemoteEmSigner,
            SyncEmSignerCertificate = Config.SyncEmSignerCertificate,
            Resolver = new WindowsTcpOwnerResolver(),
            P11ClientIdentifier = WinNative.PipeClientApp,
            Audit = Audit,
        }, new WindowsRemotePlatform());
        _remote.Log += Write;
        _remote.LinksChanged += () => Changed?.Invoke();
        _remote.TokenEvent += e => { TokenEvent?.Invoke(e); Changed?.Invoke(); };
        await _remote.StartAsync();
    }

    /// <summary>
    /// Several users on one server each need their own TLS listener: use the configured port or the next free one.
    /// </summary>
    private TlsTunnelServer? CreateTlsServer()
    {
        var cert = TunnelCertificate.LoadOrCreate(Path.Combine(AppConfig.DefaultDirectory, "tunnel.pfx"));
        var address = IPAddress.TryParse(Config.ListenAddress, out var a) ? a : IPAddress.Any;
        for (int port = Config.TunnelPort; port < Config.TunnelPort + 64; port++)
        {
            var server = new TlsTunnelServer(new IPEndPoint(address, port), cert);
            try
            {
                server.Start();
                TlsPort = port;
                if (port != Config.TunnelPort) Write($"Port {Config.TunnelPort} is used by another user; TLS tunnel listens on {port}. Enter this port on your Local PC.");
                return server;
            }
            catch (SocketException) { _ = server.DisposeAsync(); }
        }
        Write("No free TCP port for the TLS tunnel");
        return null;
    }

    public async Task StopAsync()
    {
        _watcher?.Dispose();
        _watcher = null;
        if (_local is not null) await _local.DisposeAsync();
        if (_remote is not null) await _remote.DisposeAsync();
        _tokens?.Dispose();
        _local = null;
        _remote = null;
        _tokens = null;
        _hwBackend = null;
        TlsPort = 0;
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
