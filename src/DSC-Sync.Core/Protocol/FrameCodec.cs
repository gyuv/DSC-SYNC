using System.Buffers.Binary;

namespace DscSync.Core.Protocol;

public enum FrameType : byte
{
    Hello = 1,
    Proof = 2,
    RpcRequest = 10,
    RpcResponse = 11,
    Event = 12,
    StreamOpen = 20,
    StreamOpenResult = 21,
    StreamData = 22,
    StreamClose = 23,
    Ping = 30,
    Pong = 31,
}

public readonly record struct Frame(FrameType Type, uint StreamId, byte[] Payload);

/// <summary>
/// Wire format: [u32 BE length of (type+streamId+payload)] [u8 type] [u32 BE streamId] [payload].
/// </summary>
public sealed class FrameCodec : IAsyncDisposable
{
    public const int MaxFrameSize = 16 * 1024 * 1024;
    private const int HeaderSize = 9;

    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly byte[] _header = new byte[HeaderSize];

    public FrameCodec(Stream stream) => _stream = stream;

    public Stream BaseStream => _stream;

    public async Task WriteAsync(FrameType type, uint streamId, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        if (payload.Length > MaxFrameSize) throw new ArgumentOutOfRangeException(nameof(payload), "Frame too large");
        var buffer = new byte[HeaderSize + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), (uint)(5 + payload.Length));
        buffer[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(5, 4), streamId);
        payload.Span.CopyTo(buffer.AsSpan(HeaderSize));
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(buffer, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Reads one frame; returns null on clean end of stream.</summary>
    public async Task<Frame?> ReadAsync(CancellationToken ct = default)
    {
        if (!await ReadExactAsync(_header, ct).ConfigureAwait(false)) return null;
        uint length = BinaryPrimitives.ReadUInt32BigEndian(_header.AsSpan(0, 4));
        if (length < 5 || length > MaxFrameSize + 5) throw new InvalidDataException($"Invalid frame length {length}");
        var type = (FrameType)_header[4];
        uint streamId = BinaryPrimitives.ReadUInt32BigEndian(_header.AsSpan(5, 4));
        var payload = new byte[length - 5];
        if (payload.Length > 0 && !await ReadExactAsync(payload, ct).ConfigureAwait(false))
            throw new EndOfStreamException("Connection closed in the middle of a frame");
        return new Frame(type, streamId, payload);
    }

    private async Task<bool> ReadExactAsync(Memory<byte> buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await _stream.ReadAsync(buffer[read..], ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (read == 0) return false;
                throw new EndOfStreamException("Connection closed in the middle of a frame");
            }
            read += n;
        }
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}
