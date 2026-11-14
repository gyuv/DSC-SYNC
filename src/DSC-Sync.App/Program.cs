using System.ServiceProcess;
using System.Windows;
using DscSync.App.Services;
using DscSync.App.Views;
using DscSync.Core.Audit;
using DscSync.Core.Config;

namespace DscSync.App;

public static class Program
{
    public static string ServiceConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DSC-Sync", "service.json");

    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Contains("--service", StringComparer.OrdinalIgnoreCase))
        {
            ServiceBase.Run(new DscSyncService());
            return 0;
        }

        // One instance per Windows session (each RDS user runs their own copy).
        using var mutex = new Mutex(true, @"Local\DSC-Sync-Instance", out bool first);
        using var showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\DSC-Sync-Show");
        if (!first)
        {
            showSignal.Set();
            return 0;
        }

        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("pack://application:,,,/DSC-Sync;component/Views/Theme.xaml") });
        app.DispatcherUnhandledException += (_, e) =>
        {
            Crash(e.Exception);
            e.Handled = true; // never take the signing bridge down because of a UI error
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Crash(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { Crash(e.Exception); e.SetObserved(); };

        SyncMode? forcedMode = null;
        int mi = Array.FindIndex(args, a => a.Equals("--mode", StringComparison.OrdinalIgnoreCase));
        if (mi >= 0 && mi + 1 < args.Length && Enum.TryParse<SyncMode>(args[mi + 1], true, out var m)) forcedMode = m;
        var window = new MainWindow(startMinimized: args.Contains("--minimized", StringComparer.OrdinalIgnoreCase), forcedMode);
        var showThread = new Thread(() =>
        {
            while (showSignal.WaitOne())
                app.Dispatcher.BeginInvoke(window.ShowFromTray);
        }) { IsBackground = true };
        showThread.Start();
        return app.Run(window);
    }

    private static readonly FileLog CrashLog = new();

    private static void Crash(Exception? ex)
    {
        if (ex is null) return;
        CrashLog.Write("UNHANDLED: " + ex);
    }
}

/// <summary>Headless Windows service (Local PC token source over the TLS tunnel).</summary>
public sealed class DscSyncService : ServiceBase
{
    private SyncController? _sync;

    public DscSyncService() => ServiceName = Installer.ServiceName;

    protected override void OnStart(string[] args)
    {
        var log = new FileLog();
        var config = AppConfig.Load(Program.ServiceConfigPath);
        config.Mode = SyncMode.Local;
        config.Transport = TransportPreference.TcpOnly; // services run in session 0: no RDP channel
        _sync = new SyncController(log, new AuditLog());
        _sync.StartAsync(config).GetAwaiter().GetResult();
    }

    protected override void OnStop() => _sync?.DisposeAsync().AsTask().GetAwaiter().GetResult();
}
