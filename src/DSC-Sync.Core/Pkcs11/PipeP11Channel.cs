using System.IO.Pipes;
using DscSync.Core.Protocol;

namespace DscSync.Core.Pkcs11;

/// <summary>
/// Synchronous request/response channel from DSC-Sync-P11.dll (inside Acrobat, Chrome, emSigner, …) to the
/// DSC-Sync tray app / service on the Remote VM. Uses the same frame codec as the tunnel.
/// </summary>
public sealed class PipeP11Channel : IP11Channel
{
    private readonly string _pipeName;
    private readonly int _connectTimeoutMs;
    private readonly object _lock = new();
    private NamedPipeClientStream? _pipe;
    private FrameCodec? _codec;
    private long _nextId;

    public PipeP11Channel(string pipeName = DscConstants.P11PipeName, int connectTimeoutMs = 2000)
    {
        _pipeName = pipeName;
        _connectTimeoutMs = connectTimeoutMs;
    }

    public byte[]? Call(string method, byte[]? body, int timeoutMs)
    {
        lock (_lock)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    EnsureConnected();
                    var env = new RpcEnvelope { Id = ++_nextId, Method = method, Body = body };
                    using var cts = new CancellationTokenSource(timeoutMs);
                    _codec!.WriteAsync(FrameType.RpcRequest, 0, ProtocolJson.Serialize(env, ProtocolJson.Default.RpcEnvelope), cts.Token).GetAwaiter().GetResult();
                    var frame = _codec.ReadAsync(cts.Token).GetAwaiter().GetResult()
                                ?? throw new IOException("DSC-Sync pipe closed");
                    var response = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.RpcEnvelope);
                    if (response.ErrorCode != 0) throw new RpcException(response.ErrorCode, response.Error ?? "error");
                    return response.Body;
                }
                catch (RpcException) { throw; }
                catch (OperationCanceledException)
                {
                    Reset();
                    throw new RpcException(RpcErrors.Timeout, $"DSC-Sync did not answer '{method}' in time");
                }
                catch (Exception ex) when (ex is IOException or TimeoutException or InvalidDataException or ObjectDisposedException)
                {
                    Reset();
                    if (attempt == 1) throw new RpcException(RpcErrors.NotConnected, "DSC-Sync is not running on this machine: " + ex.Message);
                }
            }
            throw new RpcException(RpcErrors.NotConnected, "DSC-Sync is not running on this machine");
        }
    }

    private void EnsureConnected()
    {
        if (_pipe is { IsConnected: true }) return;
        Reset();
        _pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        _pipe.Connect(_connectTimeoutMs);
        _codec = new FrameCodec(_pipe);
    }

    private void Reset()
    {
        try { _pipe?.Dispose(); } catch (Exception) { }
        _pipe = null;
        _codec = null;
    }

    public void Dispose()
    {
        lock (_lock) Reset();
    }
}

/// <summary>Pipe server used by DSC-Sync on the Remote VM to serve DSC-Sync-P11.dll clients.</summary>
public sealed class P11PipeServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly RpcHandler _handler;
    private readonly Func<string, NamedPipeServerStream>? _pipeFactory;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public P11PipeServer(RpcHandler handler, string pipeName = DscConstants.P11PipeName, Func<string, NamedPipeServerStream>? pipeFactory = null)
    {
        _handler = handler;
        _pipeName = pipeName;
        _pipeFactory = pipeFactory;
    }

    public int ConnectedClients;

    public void Start() => _acceptLoop = Task.Run(AcceptLoopAsync);

    private NamedPipeServerStream CreatePipe() => _pipeFactory?.Invoke(_pipeName)
        ?? new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                var connected = pipe;
                pipe = null;
                _ = Task.Run(() => ServeClientAsync(connected));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception)
            {
                pipe?.Dispose();
                try { await Task.Delay(500, _cts.Token).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe)
    {
        Interlocked.Increment(ref ConnectedClients);
        var codec = new FrameCodec(pipe);
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var frame = await codec.ReadAsync(_cts.Token).ConfigureAwait(false);
                if (frame is null) break;
                if (frame.Value.Type != FrameType.RpcRequest) continue;
                var req = ProtocolJson.Deserialize(frame.Value.Payload, ProtocolJson.Default.RpcEnvelope);
                var resp = new RpcEnvelope { Id = req.Id, Method = req.Method };
                try { resp.Body = await _handler(req.Method, req.Body, _cts.Token).ConfigureAwait(false); }
                catch (RpcException ex) { resp.ErrorCode = ex.Code; resp.Error = ex.Message; }
                catch (Exception ex) { resp.ErrorCode = RpcErrors.Internal; resp.Error = ex.Message; }
                await codec.WriteAsync(FrameType.RpcResponse, 0, ProtocolJson.Serialize(resp, ProtocolJson.Default.RpcEnvelope), _cts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception) { /* client went away */ }
        finally
        {
            Interlocked.Decrement(ref ConnectedClients);
            await codec.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_acceptLoop is not null) { try { await _acceptLoop.ConfigureAwait(false); } catch (Exception) { } }
        _cts.Dispose();
    }
}
