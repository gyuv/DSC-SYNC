using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using DscSync.Core;
using DscSync.Core.Security;
using DscSync.Tunnel.Transports;
using Microsoft.Win32.SafeHandles;

namespace DscSync.Tunnel.Dvc;

internal static class WtsNative
{
    public const uint WTS_CURRENT_SESSION = 0xFFFFFFFF;
    public const uint WTS_CHANNEL_OPTION_DYNAMIC = 0x00000001;
    public const uint WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH = 0x00000004;
    public const int WTSVirtualFileHandle = 1;
    public const int SM_REMOTESESSION = 0x1000;
    public const uint DUPLICATE_SAME_ACCESS = 2;

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern IntPtr WTSVirtualChannelOpenEx(uint sessionId, [MarshalAs(UnmanagedType.LPStr)] string virtualName, uint flags);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSVirtualChannelQuery(IntPtr hChannel, int wtsVirtualClass, out IntPtr ppBuffer, out uint pBytesReturned);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSVirtualChannelClose(IntPtr hChannel);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(IntPtr hSourceProcess, IntPtr hSource, IntPtr hTargetProcess, out IntPtr lpTarget,
        uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int index);

    public static bool IsRemoteSession => OperatingSystem.IsWindows() && GetSystemMetrics(SM_REMOTESESSION) != 0;
}

/// <summary>
/// Stream over a dynamic virtual channel file handle. Every read from a DVC handle returns one chunk prefixed with
/// an 8-byte CHANNEL_PDU_HEADER (length, flags) that must be stripped; writes are raw.
/// </summary>
public sealed class DvcStream : Stream
{
    private const int HeaderSize = 8;
    private const int MaxWrite = 32 * 1024;
    private readonly FileStream _file;
    private readonly IntPtr _channel;
    private readonly byte[] _readBuffer = new byte[64 * 1024 + HeaderSize];
    private int _pending, _pendingOffset;
    private int _disposed;

    internal DvcStream(FileStream file, IntPtr channel)
    {
        _file = file;
        _channel = channel;
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _file.Flush();
    public override Task FlushAsync(CancellationToken ct) => _file.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        while (_pending == 0)
        {
            int n = await _file.ReadAsync(_readBuffer, ct).ConfigureAwait(false);
            if (n == 0) return 0;
            if (n <= HeaderSize) continue;
            _pendingOffset = HeaderSize;
            _pending = n - HeaderSize;
        }
        int take = Math.Min(buffer.Length, _pending);
        _readBuffer.AsMemory(_pendingOffset, take).CopyTo(buffer);
        _pendingOffset += take;
        _pending -= take;
        return take;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        for (int i = 0; i < buffer.Length; i += MaxWrite)
            await _file.WriteAsync(buffer.Slice(i, Math.Min(MaxWrite, buffer.Length - i)), ct).ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { _file.Dispose(); } catch (IOException) { }
            WtsNative.WTSVirtualChannelClose(_channel);
        }
        base.Dispose(disposing);
    }
}

/// <summary>
/// Remote-VM side of the RDP Dynamic Virtual Channel. Opens "DSCSYNC" inside the current RDP session; succeeds only
/// when the mstsc client has the DSC-Sync plug-in loaded (i.e. the Local PC runs DSC-Sync in Local mode).
/// </summary>
public sealed class DvcServerConnector : ITransportConnector
{
    public string Kind => TransportKinds.RdpDvc;
    public bool IsAvailable => WtsNative.IsRemoteSession;
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(3);
    public string? LastError { get; private set; }

    public async Task<TransportConnection> ConnectAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("RDP DVC requires Windows");
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (WtsNative.IsRemoteSession && TryOpen(out var stream))
            {
                LastError = null;
                return new TransportConnection
                {
                    Stream = stream!,
                    Kind = Kind,
                    Peer = "mstsc client",
                    ChannelBinding = PairingHandshake.DvcChannelBinding,
                };
            }
            await Task.Delay(RetryDelay, ct).ConfigureAwait(false);
        }
    }

    private bool TryOpen(out DvcStream? stream)
    {
        stream = null;
        IntPtr channel = WtsNative.WTSVirtualChannelOpenEx(WtsNative.WTS_CURRENT_SESSION, DscConstants.DvcChannelName,
            WtsNative.WTS_CHANNEL_OPTION_DYNAMIC | WtsNative.WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH);
        if (channel == IntPtr.Zero)
        {
            LastError = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return false;
        }
        if (!WtsNative.WTSVirtualChannelQuery(channel, WtsNative.WTSVirtualFileHandle, out var buffer, out var len) || len < IntPtr.Size)
        {
            LastError = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            WtsNative.WTSVirtualChannelClose(channel);
            return false;
        }
        IntPtr fileHandle = Marshal.ReadIntPtr(buffer);
        bool dup = WtsNative.DuplicateHandle(WtsNative.GetCurrentProcess(), fileHandle, WtsNative.GetCurrentProcess(), out var duplicated, 0, false, WtsNative.DUPLICATE_SAME_ACCESS);
        WtsNative.WTSFreeMemory(buffer);
        if (!dup)
        {
            LastError = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            WtsNative.WTSVirtualChannelClose(channel);
            return false;
        }
        var safe = new SafeFileHandle(duplicated, ownsHandle: true);
        var file = new FileStream(safe, FileAccess.ReadWrite, bufferSize: 0, isAsync: true);
        stream = new DvcStream(file, channel);
        return true;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>
/// Local-PC side of the DVC: the mstsc plug-in (DSC-Sync.RdpPlugin.comhost.dll) connects to this pipe whenever the
/// remote DSC-Sync opens the "DSCSYNC" channel, and relays the channel bytes 1:1.
/// </summary>
public sealed class DvcPluginPipeConnector : ITransportConnector
{
    private readonly string _pipeName;

    public DvcPluginPipeConnector(string pipeName = DscConstants.DvcPluginPipeName) => _pipeName = pipeName;

    public string Kind => TransportKinds.RdpDvc;
    public bool IsAvailable => true;

    public async Task<TransportConnection> ConnectAsync(CancellationToken ct)
    {
        var pipe = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        return new TransportConnection
        {
            Stream = pipe,
            Kind = Kind,
            Peer = "RDP session (mstsc plug-in)",
            ChannelBinding = PairingHandshake.DvcChannelBinding,
        };
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
