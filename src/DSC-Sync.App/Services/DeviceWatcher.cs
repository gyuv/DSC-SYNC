using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace DscSync.App.Services;

/// <summary>
/// Listens for WM_DEVICECHANGE on a message-only window for USB devices and smart-card readers, so a token swap
/// on the Local PC is detected instantly (not by polling).
/// </summary>
public sealed class DeviceWatcher : IDisposable
{
    private static readonly Guid GUID_DEVINTERFACE_USB_DEVICE = new("A5DCBF10-6530-11D2-901F-00C04FB951ED");
    private static readonly Guid GUID_DEVINTERFACE_SMARTCARD_READER = new("50DD5230-BA8A-11D1-BF5D-0000F805F530");
    private const int WM_DEVICECHANGE = 0x0219;
    private const int DBT_DEVICEARRIVAL = 0x8000;
    private const int DBT_DEVICEREMOVECOMPLETE = 0x8004;
    private const int DBT_DEVNODES_CHANGED = 0x0007;
    private const int DBT_DEVTYP_DEVICEINTERFACE = 5;
    private const int DEVICE_NOTIFY_WINDOW_HANDLE = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct DEV_BROADCAST_DEVICEINTERFACE
    {
        public int dbcc_size;
        public int dbcc_devicetype;
        public int dbcc_reserved;
        public Guid dbcc_classguid;
        public short dbcc_name;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr RegisterDeviceNotification(IntPtr hRecipient, ref DEV_BROADCAST_DEVICEINTERFACE filter, int flags);

    [DllImport("user32.dll")]
    private static extern bool UnregisterDeviceNotification(IntPtr handle);

    private readonly HwndSource _source;
    private readonly List<IntPtr> _registrations = new();

    /// <summary>Raised with true on arrival, false on removal.</summary>
    public event Action<bool>? DeviceChanged;

    public DeviceWatcher()
    {
        var p = new HwndSourceParameters("DSC-Sync DeviceWatcher") { Width = 0, Height = 0, WindowStyle = 0, ParentWindow = new IntPtr(-3) /* HWND_MESSAGE */ };
        _source = new HwndSource(p);
        _source.AddHook(WndProc);
        foreach (var g in new[] { GUID_DEVINTERFACE_USB_DEVICE, GUID_DEVINTERFACE_SMARTCARD_READER })
        {
            var filter = new DEV_BROADCAST_DEVICEINTERFACE
            {
                dbcc_size = Marshal.SizeOf<DEV_BROADCAST_DEVICEINTERFACE>(),
                dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE,
                dbcc_classguid = g,
            };
            var h = RegisterDeviceNotification(_source.Handle, ref filter, DEVICE_NOTIFY_WINDOW_HANDLE);
            if (h != IntPtr.Zero) _registrations.Add(h);
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_DEVICECHANGE)
        {
            int ev = wParam.ToInt32();
            if (ev == DBT_DEVICEARRIVAL) DeviceChanged?.Invoke(true);
            else if (ev == DBT_DEVICEREMOVECOMPLETE) DeviceChanged?.Invoke(false);
            else if (ev == DBT_DEVNODES_CHANGED) DeviceChanged?.Invoke(true);
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        foreach (var h in _registrations) UnregisterDeviceNotification(h);
        _registrations.Clear();
        _source.RemoveHook(WndProc);
        _source.Dispose();
    }
}
