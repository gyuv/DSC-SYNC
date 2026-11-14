using DscSync.Core.Protocol;
using DscSync.Core.Security;

namespace DscSync.Tunnel.Transports;

public static class TransportKinds
{
    public const string RdpDvc = "RDP DVC";
    public const string TlsTunnel = "TLS Tunnel";
    public const string InMemory = "In-Memory";
}

/// <summary>A raw, connected byte stream to the peer plus the data needed to authenticate it.</summary>
public sealed class TransportConnection : IAsyncDisposable
{
    public required Stream Stream { get; init; }
    public required string Kind { get; init; }
    public required string Peer { get; init; }
    public required byte[] ChannelBinding { get; init; }

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

/// <summary>Produces connections; for servers each call returns the next accepted connection.</summary>
public interface ITransportConnector : IAsyncDisposable
{
    string Kind { get; }
    /// <summary>True when the connector can be used on this machine (e.g. running inside an RDP session).</summary>
    bool IsAvailable { get; }
    Task<TransportConnection> ConnectAsync(CancellationToken ct);
}

public static class SessionEstablisher
{
    /// <summary>Authenticates the connection with the pairing PIN and wraps it into a started <see cref="MuxConnection"/>.</summary>
    public static async Task<MuxConnection> EstablishAsync(TransportConnection connection, string role, string pin, TimeSpan timeout, CancellationToken ct, Action<MuxConnection>? configure = null)
    {
        var codec = new FrameCodec(connection.Stream);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        HandshakeResult result;
        try
        {
            result = await PairingHandshake.RunAsync(codec, role, pin, connection.ChannelBinding, cts.Token).ConfigureAwait(false);
        }
        catch
        {
            await codec.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        var mux = new MuxConnection(codec, isHostSide: role == PairingHandshake.RoleRemote, connection.Kind, $"{result.PeerMachine} ({connection.Peer})");
        configure?.Invoke(mux);
        mux.Start();
        return mux;
    }
}
