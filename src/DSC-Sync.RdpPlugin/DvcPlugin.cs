using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using DscSync.Core;

namespace DscSync.RdpPlugin;

/// <summary>
/// Minimal hand-written COM implementation of IWTSPlugin / IWTSListenerCallback / IWTSVirtualChannelCallback.
/// mstsc.exe loads this DLL and calls <c>VirtualChannelGetInstance</c>. When the DSC-Sync instance on the remote
/// server opens the "DSCSYNC" dynamic channel, the bytes are relayed 1:1 to the local DSC-Sync app via a named pipe.
/// </summary>
public static unsafe class DvcPlugin
{
    private const int S_OK = 0;
    private const int E_NOINTERFACE = unchecked((int)0x80004002);
    private const int E_POINTER = unchecked((int)0x80004003);
    private const int E_FAIL = unchecked((int)0x80004005);

    private static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");
    private static readonly Guid IID_IWTSPlugin = new("A1230201-1439-4E62-A414-190D0AC3D40E");
    private static readonly Guid IID_IWTSListenerCallback = new("A1230203-D6A7-11D8-B9FD-000BDBD1F198");
    private static readonly Guid IID_IWTSVirtualChannelCallback = new("A1230204-D6A7-11D8-B9FD-000BDBD1F198");

    // COM object layout: [vtable*][id]
    private struct ComObject
    {
        public void** Vtbl;
        public nint Id;
    }

    private static readonly void** PluginVtbl = CreatePluginVtbl();
    private static readonly void** ListenerVtbl = CreateListenerVtbl();
    private static readonly void** ChannelVtbl = CreateChannelVtbl();
    private static ComObject* _plugin;
    private static ComObject* _listener;
    private static readonly ConcurrentDictionary<nint, ChannelBridge> Channels = new();
    private static long _nextChannel;

    private static void** Alloc(int slots) => (void**)NativeMemory.AllocZeroed((nuint)(slots * sizeof(void*)));

    private static void** CreatePluginVtbl()
    {
        var v = Alloc(7);
        v[0] = (delegate* unmanaged[Stdcall]<ComObject*, Guid*, void**, int>)&PluginQI;
        v[1] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&AddRef;
        v[2] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&Release;
        v[3] = (delegate* unmanaged[Stdcall]<ComObject*, void*, int>)&Initialize;
        v[4] = (delegate* unmanaged[Stdcall]<ComObject*, int>)&Connected;
        v[5] = (delegate* unmanaged[Stdcall]<ComObject*, uint, int>)&Disconnected;
        v[6] = (delegate* unmanaged[Stdcall]<ComObject*, int>)&Terminated;
        return v;
    }

    private static void** CreateListenerVtbl()
    {
        var v = Alloc(4);
        v[0] = (delegate* unmanaged[Stdcall]<ComObject*, Guid*, void**, int>)&ListenerQI;
        v[1] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&AddRef;
        v[2] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&Release;
        v[3] = (delegate* unmanaged[Stdcall]<ComObject*, void*, char*, int*, void**, int>)&OnNewChannelConnection;
        return v;
    }

    private static void** CreateChannelVtbl()
    {
        var v = Alloc(5);
        v[0] = (delegate* unmanaged[Stdcall]<ComObject*, Guid*, void**, int>)&ChannelQI;
        v[1] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&AddRef;
        v[2] = (delegate* unmanaged[Stdcall]<ComObject*, uint>)&Release;
        v[3] = (delegate* unmanaged[Stdcall]<ComObject*, uint, byte*, int>)&OnDataReceived;
        v[4] = (delegate* unmanaged[Stdcall]<ComObject*, int>)&OnClose;
        return v;
    }

    private static ComObject* NewObject(void** vtbl, nint id)
    {
        var o = (ComObject*)NativeMemory.AllocZeroed((nuint)sizeof(ComObject));
        o->Vtbl = vtbl;
        o->Id = id;
        return o;
    }

    /// <summary>Entry point mstsc uses for DLL-path registered dynamic virtual channel plug-ins.</summary>
    [UnmanagedCallersOnly(EntryPoint = "VirtualChannelGetInstance", CallConvs = new[] { typeof(CallConvStdcall) })]
    public static int VirtualChannelGetInstance(Guid* refiid, uint* pNumObjs, void** ppObjArray)
    {
        if (refiid == null || pNumObjs == null) return E_POINTER;
        if (*refiid != IID_IWTSPlugin) return E_NOINTERFACE;
        if (ppObjArray == null)
        {
            *pNumObjs = 1;
            return S_OK;
        }
        if (*pNumObjs < 1) return E_FAIL;
        if (_plugin == null) _plugin = NewObject(PluginVtbl, 0);
        ppObjArray[0] = _plugin;
        *pNumObjs = 1;
        return S_OK;
    }

    // Objects live for the lifetime of mstsc; reference counts are therefore fixed.
    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint AddRef(ComObject* self) => 2;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint Release(ComObject* self) => 1;

    private static int QI(ComObject* self, Guid* riid, void** ppv, Guid own)
    {
        if (ppv == null) return E_POINTER;
        if (*riid == IID_IUnknown || *riid == own)
        {
            *ppv = self;
            return S_OK;
        }
        *ppv = null;
        return E_NOINTERFACE;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int PluginQI(ComObject* self, Guid* riid, void** ppv) => QI(self, riid, ppv, IID_IWTSPlugin);

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int ListenerQI(ComObject* self, Guid* riid, void** ppv) => QI(self, riid, ppv, IID_IWTSListenerCallback);

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int ChannelQI(ComObject* self, Guid* riid, void** ppv) => QI(self, riid, ppv, IID_IWTSVirtualChannelCallback);

    // ---------------------------------------------------------------- IWTSPlugin

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Initialize(ComObject* self, void* channelManager)
    {
        if (channelManager == null) return E_POINTER;
        try
        {
            if (_listener == null) _listener = NewObject(ListenerVtbl, 0);
            // IWTSVirtualChannelManager::CreateListener(this, const char*, ULONG, IWTSListenerCallback*, IWTSListener**)
            var vtbl = *(void***)channelManager;
            var createListener = (delegate* unmanaged[Stdcall]<void*, byte*, uint, void*, void**, int>)vtbl[3];
            var name = System.Text.Encoding.ASCII.GetBytes(DscConstants.DvcChannelName + "\0");
            void* listener = null;
            fixed (byte* pName = name)
                return createListener(channelManager, pName, 0, _listener, &listener);
        }
        catch (Exception) { return E_FAIL; }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Connected(ComObject* self) => S_OK;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Disconnected(ComObject* self, uint reason)
    {
        foreach (var c in Channels.Values) c.Dispose();
        Channels.Clear();
        return S_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Terminated(ComObject* self)
    {
        foreach (var c in Channels.Values) c.Dispose();
        Channels.Clear();
        return S_OK;
    }

    // ---------------------------------------------------------------- IWTSListenerCallback

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int OnNewChannelConnection(ComObject* self, void* channel, char* data, int* pbAccept, void** ppCallback)
    {
        if (pbAccept == null || ppCallback == null || channel == null) return E_POINTER;
        *pbAccept = 0;
        *ppCallback = null;
        try
        {
            var bridge = ChannelBridge.TryCreate((nint)channel);
            if (bridge is null) return S_OK; // local DSC-Sync not running: refuse, remote keeps retrying
            nint id = (nint)Interlocked.Increment(ref _nextChannel);
            Channels[id] = bridge;
            *ppCallback = NewObject(ChannelVtbl, id);
            *pbAccept = 1;
            bridge.StartPump(() => Channels.TryRemove(id, out _));
            return S_OK;
        }
        catch (Exception) { return E_FAIL; }
    }

    // ---------------------------------------------------------------- IWTSVirtualChannelCallback

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int OnDataReceived(ComObject* self, uint cb, byte* buffer)
    {
        if (!Channels.TryGetValue(self->Id, out var bridge)) return S_OK;
        try { bridge.ToLocal(new ReadOnlySpan<byte>(buffer, (int)cb)); }
        catch (Exception) { bridge.Dispose(); }
        return S_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int OnClose(ComObject* self)
    {
        if (Channels.TryRemove(self->Id, out var bridge)) bridge.Dispose();
        return S_OK;
    }

    /// <summary>Relays one virtual channel to the local DSC-Sync app's pipe.</summary>
    private sealed class ChannelBridge : IDisposable
    {
        private readonly nint _channel;
        private readonly NamedPipeClientStream _pipe;
        private int _disposed;

        private ChannelBridge(nint channel, NamedPipeClientStream pipe)
        {
            _channel = channel;
            _pipe = pipe;
            var vtbl = *(void***)channel;
            ((delegate* unmanaged[Stdcall]<nint, uint>)vtbl[1])(channel); // AddRef
        }

        public static ChannelBridge? TryCreate(nint channel)
        {
            var pipe = new NamedPipeClientStream(".", $"{DscConstants.DvcPluginPipeName}-{SessionInfo.CurrentSessionId}",
                PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                pipe.Connect(1500);
                return new ChannelBridge(channel, pipe);
            }
            catch (Exception)
            {
                pipe.Dispose();
                return null;
            }
        }

        public void ToLocal(ReadOnlySpan<byte> data)
        {
            _pipe.Write(data);
            _pipe.Flush();
        }

        public void StartPump(Action onEnd)
        {
            var t = new Thread(() =>
            {
                var buffer = new byte[32 * 1024];
                try
                {
                    while (Volatile.Read(ref _disposed) == 0)
                    {
                        int n = _pipe.Read(buffer, 0, buffer.Length);
                        if (n <= 0) break;
                        fixed (byte* p = buffer)
                        {
                            var vtbl = *(void***)_channel;
                            int hr = ((delegate* unmanaged[Stdcall]<nint, uint, byte*, void*, int>)vtbl[3])(_channel, (uint)n, p, null);
                            if (hr < 0) break;
                        }
                    }
                }
                catch (Exception) { }
                Dispose();
                onEnd();
            }) { IsBackground = true, Name = "DSC-Sync DVC pump" };
            t.Start();
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { _pipe.Dispose(); } catch (Exception) { }
            try
            {
                var vtbl = *(void***)_channel;
                ((delegate* unmanaged[Stdcall]<nint, int>)vtbl[4])(_channel); // Close
                ((delegate* unmanaged[Stdcall]<nint, uint>)vtbl[2])(_channel); // Release
            }
            catch (Exception) { }
        }
    }
}
