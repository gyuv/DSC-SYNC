using System.Collections.Concurrent;
using System.Threading.Channels;

namespace DscSync.Core.Protocol;

public delegate Task<byte[]?> RpcHandler(string method, byte[]? body, CancellationToken ct);
public delegate Task<Stream?> StreamOpenHandler(int port, CancellationToken ct);

/// <summary>
/// Multiplexes RPC calls, events and many independent byte streams over one authenticated transport stream
/// (RDP DVC or TLS tunnel).
/// </summary>
public sealed class MuxConnection : IAsyncDisposable
{
    private readonly FrameCodec _codec;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<RpcEnvelope>> _pendingCalls = new();
    private readonly ConcurrentDictionary<uint, MuxStream> _streams = new();
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<bool>> _pendingOpens = new();
    private readonly CancellationTokenSource _cts = new();
    private long _nextCallId;
    private uint _nextStreamId;
    private Task? _readLoop;
    private Task? _keepAlive;
    private long _lastReceiveTicks = Environment.TickCount64;
    private int _closed;

    public MuxConnection(FrameCodec codec, bool isHostSide, string transportKind, string peerName)
    {
        _codec = codec;
        _nextStreamId = isHostSide ? 1u : 2u;
        TransportKind = transportKind;
        PeerName = peerName;
    }

    public string TransportKind { get; }
    public string PeerName { get; }
    public string PeerMachine { get; init; } = "";
    public string PeerUser { get; init; } = "";
    public RpcHandler? RpcHandler { get; set; }
    public StreamOpenHandler? StreamOpenHandler { get; set; }
    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.FromSeconds(10);
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromSeconds(45);
    public int ActiveStreamCount => _streams.Count;
    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    public event Action<string, byte[]?>? EventReceived;
    public event Action<Exception?>? Closed;

    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Completion => _completion.Task;

    public void Start()
    {
        _readLoop = Task.Run(ReadLoopAsync);
        _keepAlive = Task.Run(KeepAliveLoopAsync);
    }

    public async Task<byte[]?> CallAsync(string method, byte[]? body, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        ThrowIfClosed();
        long id = Interlocked.Increment(ref _nextCallId);
        var tcs = new TaskCompletionSource<RpcEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingCalls[id] = tcs;
        try
        {
            var env = new RpcEnvelope { Id = id, Method = method, Body = body };
            await _codec.WriteAsync(FrameType.RpcRequest, 0, ProtocolJson.Serialize(env, ProtocolJson.Default.RpcEnvelope), ct).ConfigureAwait(false);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            linked.CancelAfter(timeout ?? TimeSpan.FromSeconds(60));
            RpcEnvelope response;
            try
            {
                response = await tcs.Task.WaitAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                if (IsClosed) throw new RpcException(RpcErrors.NotConnected, "Connection closed");
                throw new RpcException(RpcErrors.Timeout, $"RPC '{method}' timed out");
            }
            if (response.ErrorCode != 0) throw new RpcException(response.ErrorCode, response.Error ?? "Remote error");
            return response.Body;
        }
        finally
        {
            _pendingCalls.TryRemove(id, out _);
        }
    }

    public Task SendEventAsync(string name, byte[]? body, CancellationToken ct = default)
    {
        ThrowIfClosed();
        var env = new RpcEnvelope { Method = name, Body = body };
        return _codec.WriteAsync(FrameType.Event, 0, ProtocolJson.Serialize(env, ProtocolJson.Default.RpcEnvelope), ct);
    }

    /// <summary>Opens a new byte stream that the peer connects to 127.0.0.1:<paramref name="port"/>.</summary>
    public async Task<MuxStream> OpenStreamAsync(int port, CancellationToken ct = default)
    {
        ThrowIfClosed();
        uint id = Interlocked.Add(ref _nextStreamId, 2) - 2;
        var stream = new MuxStream(this, id, port);
        _streams[id] = stream;
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingOpens[id] = tcs;
        try
        {
            await _codec.WriteAsync(FrameType.StreamOpen, id, ProtocolJson.Serialize(new PortRequest { Port = port }, ProtocolJson.Default.PortRequest), ct).ConfigureAwait(false);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            linked.CancelAfter(TimeSpan.FromSeconds(15));
            bool ok;
            try { ok = await tcs.Task.WaitAsync(linked.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { ok = false; }
            if (!ok)
            {
                _streams.TryRemove(id, out _);
                stream.CompleteIncoming();
                throw new IOException($"Peer refused or failed to connect stream to port {port}");
            }
            return stream;
        }
        finally
        {
            _pendingOpens.TryRemove(id, out _);
        }
    }

    /// <summary>Aborts every multiplexed stream (used on token hot-swap to kill stale keep-alive connections).</summary>
    public void CloseAllStreams()
    {
        foreach (var s in _streams.Values) s.Dispose();
    }

    internal Task SendStreamDataAsync(uint id, ReadOnlyMemory<byte> data, CancellationToken ct)
        => _codec.WriteAsync(FrameType.StreamData, id, data, ct);

    internal void OnLocalStreamClosed(uint id)
    {
        if (_streams.TryRemove(id, out _) && !IsClosed)
        {
            _ = SafeWriteAsync(FrameType.StreamClose, id, Array.Empty<byte>());
        }
    }

    private async Task SafeWriteAsync(FrameType type, uint id, byte[] payload)
    {
        try { await _codec.WriteAsync(type, id, payload, _cts.Token).ConfigureAwait(false); }
        catch (Exception) { /* connection is being torn down; close path handles cleanup */ }
    }

    private async Task ReadLoopAsync()
    {
        Exception? error = null;
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var frame = await _codec.ReadAsync(_cts.Token).ConfigureAwait(false);
                if (frame is null) break;
                Interlocked.Exchange(ref _lastReceiveTicks, Environment.TickCount64);
                await DispatchAsync(frame.Value).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { error = ex; }
        await CloseAsync(error).ConfigureAwait(false);
    }

    private async Task DispatchAsync(Frame frame)
    {
        switch (frame.Type)
        {
            case FrameType.RpcRequest:
                {
                    var env = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.RpcEnvelope);
                    _ = Task.Run(() => HandleRpcAsync(env));
                    break;
                }
            case FrameType.RpcResponse:
                {
                    var env = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.RpcEnvelope);
                    if (_pendingCalls.TryGetValue(env.Id, out var tcs)) tcs.TrySetResult(env);
                    break;
                }
            case FrameType.Event:
                {
                    var env = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.RpcEnvelope);
                    try { EventReceived?.Invoke(env.Method, env.Body); }
                    catch (Exception) { /* subscriber errors must never kill the transport */ }
                    break;
                }
            case FrameType.StreamOpen:
                {
                    var req = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.PortRequest);
                    _ = Task.Run(() => HandleStreamOpenAsync(frame.StreamId, req.Port));
                    break;
                }
            case FrameType.StreamOpenResult:
                if (_pendingOpens.TryGetValue(frame.StreamId, out var open))
                    open.TrySetResult(frame.Payload.Length > 0 && frame.Payload[0] == 1);
                break;
            case FrameType.StreamData:
                if (_streams.TryGetValue(frame.StreamId, out var s)) s.EnqueueIncoming(frame.Payload);
                break;
            case FrameType.StreamClose:
                if (_streams.TryRemove(frame.StreamId, out var closed)) closed.CompleteIncoming();
                break;
            case FrameType.Ping:
                await SafeWriteAsync(FrameType.Pong, 0, frame.Payload).ConfigureAwait(false);
                break;
            case FrameType.Pong:
                break;
            default:
                throw new InvalidDataException($"Unexpected frame type {frame.Type}");
        }
    }

    private async Task HandleRpcAsync(RpcEnvelope request)
    {
        var response = new RpcEnvelope { Id = request.Id, Method = request.Method };
        try
        {
            if (RpcHandler is null) throw new RpcException(RpcErrors.UnknownMethod, "No RPC handler registered");
            response.Body = await RpcHandler(request.Method, request.Body, _cts.Token).ConfigureAwait(false);
        }
        catch (RpcException ex)
        {
            response.ErrorCode = ex.Code;
            response.Error = ex.Message;
        }
        catch (Exception ex)
        {
            response.ErrorCode = RpcErrors.Internal;
            response.Error = ex.Message;
        }
        await SafeWriteAsync(FrameType.RpcResponse, 0, ProtocolJson.Serialize(response, ProtocolJson.Default.RpcEnvelope)).ConfigureAwait(false);
    }

    private async Task HandleStreamOpenAsync(uint id, int port)
    {
        Stream? target = null;
        try
        {
            if (StreamOpenHandler is not null) target = await StreamOpenHandler(port, _cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            target = null;
        }
        if (target is null)
        {
            await SafeWriteAsync(FrameType.StreamOpenResult, id, new byte[] { 0 }).ConfigureAwait(false);
            return;
        }
        var mux = new MuxStream(this, id, port);
        _streams[id] = mux;
        await SafeWriteAsync(FrameType.StreamOpenResult, id, new byte[] { 1 }).ConfigureAwait(false);
        await StreamPump.BridgeAsync(mux, target, _cts.Token).ConfigureAwait(false);
    }

    private async Task KeepAliveLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                await Task.Delay(KeepAliveInterval, _cts.Token).ConfigureAwait(false);
                long idleMs = Environment.TickCount64 - Interlocked.Read(ref _lastReceiveTicks);
                if (idleMs > IdleTimeout.TotalMilliseconds)
                {
                    await CloseAsync(new TimeoutException("Peer stopped responding")).ConfigureAwait(false);
                    return;
                }
                await _codec.WriteAsync(FrameType.Ping, 0, BitConverter.GetBytes(DateTime.UtcNow.Ticks), _cts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { await CloseAsync(ex).ConfigureAwait(false); }
    }

    private async Task CloseAsync(Exception? error)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _cts.Cancel();
        foreach (var call in _pendingCalls.Values) call.TrySetCanceled();
        foreach (var open in _pendingOpens.Values) open.TrySetResult(false);
        foreach (var s in _streams.Values) s.CompleteIncoming();
        _streams.Clear();
        try { await _codec.DisposeAsync().ConfigureAwait(false); } catch (Exception) { }
        try { Closed?.Invoke(error); } catch (Exception) { }
        _completion.TrySetResult();
    }

    private void ThrowIfClosed()
    {
        if (IsClosed) throw new RpcException(RpcErrors.NotConnected, "Connection closed");
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync(null).ConfigureAwait(false);
        _cts.Dispose();
    }
}

/// <summary>A single multiplexed, full-duplex byte stream.</summary>
public sealed class MuxStream : Stream
{
    private const int MaxChunk = 32 * 1024;
    private readonly MuxConnection _owner;
    private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true });
    private byte[]? _current;
    private int _currentOffset;
    private int _disposed;

    internal MuxStream(MuxConnection owner, uint id, int port)
    {
        _owner = owner;
        Id = id;
        Port = port;
    }

    public uint Id { get; }
    public int Port { get; }

    internal void EnqueueIncoming(byte[] data) => _incoming.Writer.TryWrite(data);
    internal void CompleteIncoming() => _incoming.Writer.TryComplete();

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length == 0) return 0;
        while (_current is null || _currentOffset >= _current.Length)
        {
            if (!await _incoming.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false)) return 0;
            if (_incoming.Reader.TryRead(out var next)) { _current = next; _currentOffset = 0; }
        }
        int n = Math.Min(buffer.Length, _current.Length - _currentOffset);
        _current.AsMemory(_currentOffset, n).CopyTo(buffer);
        _currentOffset += n;
        return n;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(MuxStream));
        for (int i = 0; i < buffer.Length; i += MaxChunk)
        {
            var chunk = buffer.Slice(i, Math.Min(MaxChunk, buffer.Length - i));
            await _owner.SendStreamDataAsync(Id, chunk, cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _incoming.Writer.TryComplete();
            _owner.OnLocalStreamClosed(Id);
        }
        base.Dispose(disposing);
    }
}

public static class StreamPump
{
    /// <summary>Copies bytes in both directions until either side closes, then disposes both.</summary>
    public static async Task BridgeAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = CopyAsync(a, b, cts.Token);
        var t2 = CopyAsync(b, a, cts.Token);
        await Task.WhenAny(t1, t2).ConfigureAwait(false);
        cts.Cancel();
        try { a.Dispose(); } catch (Exception) { }
        try { b.Dispose(); } catch (Exception) { }
        try { await Task.WhenAll(t1, t2).ConfigureAwait(false); } catch (Exception) { }
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[32 * 1024];
        try
        {
            while (true)
            {
                int n = await from.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (n == 0) break;
                await to.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception) { /* either side closed */ }
    }
}
