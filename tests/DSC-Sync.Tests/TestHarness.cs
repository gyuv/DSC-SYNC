using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge;
using DscSync.Pkcs11Bridge.Engine;
using DscSync.Pkcs11Bridge.Simulation;
using DscSync.Tunnel.Proxy;
using DscSync.Tunnel.Transports;

namespace DscSync.Tests;

/// <summary>Spins up a Local agent and a Remote host linked through a real TLS tunnel on loopback.</summary>
public sealed class LinkedPair : IAsyncDisposable
{
    public const string Pin = "246810";
    public required MockTokenBackend Backend { get; init; }
    public required TokenManager Tokens { get; init; }
    public required LocalAgent Local { get; init; }
    public required RemoteHost Remote { get; init; }
    public required string P11Pipe { get; init; }
    public required List<int> ProxyPorts { get; init; }

    public static async Task<LinkedPair> CreateAsync(MockToken? initialToken = null, List<int>? proxyPorts = null,
        Func<int, int>? mapLocalPort = null, string? remotePin = null, int? sessionId = null,
        DscSync.Tunnel.Proxy.IConnectionOwnerResolver? resolver = null, string? proxyPrefix = null, DscSync.Core.Audit.AuditLog? audit = null,
        bool startPortBroker = true)
    {
        var backend = new MockTokenBackend();
        if (initialToken is not null) backend.Insert(initialToken);
        var tokens = new TokenManager(backend) { Debounce = TimeSpan.FromMilliseconds(20) };
        tokens.Rescan(reload: true);

        var server = new TlsTunnelServer(new IPEndPoint(IPAddress.Loopback, 0), TunnelCertificate.CreateSelfSigned());
        server.Start();
        string pipe = "dscsync-test-" + Guid.NewGuid().ToString("N")[..12];
        proxyPorts ??= new List<int>();
        var remote = new RemoteHost(new ITransportConnector[] { server }, remotePin ?? Pin, new RemoteHostOptions
        {
            EmSignerPorts = proxyPorts,
            EnablePortProxy = proxyPorts.Count > 0,
            StopLocalEmSigner = false,
            SyncEmSignerCertificate = false,
            P11PipeName = pipe,
            ProxyPipePrefix = proxyPrefix ?? pipe + "-proxy-",
            // Must match what the resolver reports for this process (the real RDS session id on Windows).
            SessionId = sessionId ?? DscSync.Core.SessionInfo.CurrentSessionId,
            Resolver = resolver ?? new DscSync.Tunnel.Proxy.CurrentSessionResolver(),
            Audit = audit,
        }, new NullRemotePlatform()) { RetryDelay = TimeSpan.FromMilliseconds(200) };
        await remote.StartAsync();

        var target = new LocalPortTarget(proxyPorts);
        if (mapLocalPort is not null) target.MapPort = mapLocalPort;
        var local = new LocalAgent(tokens, new ITransportConnector[] { new TlsTunnelClient("127.0.0.1", server.BoundPort) }, Pin, target)
        {
            RetryDelay = TimeSpan.FromMilliseconds(200),
        };
        local.Start();
        return new LinkedPair { Backend = backend, Tokens = tokens, Local = local, Remote = remote, P11Pipe = pipe, ProxyPorts = proxyPorts };
    }

    public Task WaitLinkedAsync(TimeSpan? timeout = null) =>
        TestUtil.WaitUntilAsync(() => Remote.IsConnected && Local.IsLinked, timeout ?? TimeSpan.FromSeconds(20));

    public async ValueTask DisposeAsync()
    {
        await Local.DisposeAsync();
        await Remote.DisposeAsync();
        Tokens.Dispose();
    }
}

public static class TestUtil
{
    public static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (!condition())
        {
            if (sw.Elapsed > timeout) throw new TimeoutException("Condition not met within " + timeout);
            await Task.Delay(10);
        }
    }

    public static int FreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>Connected in-memory duplex stream pair (via a named pipe).</summary>
    public static async Task<(Stream A, Stream B)> CreateDuplexAsync()
    {
        string name = "dscsync-duplex-" + Guid.NewGuid().ToString("N")[..12];
        var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536);
        var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync();
        await client.ConnectAsync(5000);
        await accept;
        return (server, client);
    }

    public static async Task<(MuxConnection Host, MuxConnection Client)> CreateMuxPairAsync(Action<MuxConnection>? configureHost = null, Action<MuxConnection>? configureClient = null)
    {
        var (a, b) = await CreateDuplexAsync();
        var host = new MuxConnection(new FrameCodec(a), true, "test", "client");
        var client = new MuxConnection(new FrameCodec(b), false, "test", "host");
        configureHost?.Invoke(host);
        configureClient?.Invoke(client);
        host.Start();
        client.Start();
        return (host, client);
    }
}
