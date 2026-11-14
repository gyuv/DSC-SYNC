using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using DscSync.App.Services;
using DscSync.Core.Audit;
using DscSync.Core.Config;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge.Crypto;
using DscSync.Pkcs11Bridge.Pdf;
using Microsoft.Win32;
using DrawingColor = System.Drawing.Color;

namespace DscSync.App.Views;

public sealed class CertChoice
{
    public required TokenInfoDto Token { get; init; }
    public required CertificateDto Certificate { get; init; }
    public string Display => $"{Certificate.SubjectCommonName}  •  {Token.Vendor}  •  exp {Certificate.NotAfter.ToLocalTime():dd-MMM-yyyy}";
}

public partial class MainWindow : Window
{
    private readonly FileLog _fileLog = new();
    private readonly AuditLog _audit = new();
    private readonly SyncController _sync;
    private readonly Diagnostics _diagnostics;
    private readonly TrayIcon _tray;
    private readonly ObservableCollection<string> _log = new();
    private readonly DispatcherTimer _healthTimer;
    private readonly DispatcherTimer _uiDebounce;
    private readonly bool _startMinimized;
    private AppConfig _config;
    private bool _exiting;
    private bool _loadingSettings;
    private readonly SyncMode? _forcedMode;

    // PDF signer state
    private string? _pdfPath;
    private int _pdfPage = 1, _pdfPages;
    private (float W, float H) _pageSize;
    private Point? _dragStart;
    private Rect? _sigRect;
    private string? _lastSigned;

    public MainWindow(bool startMinimized, SyncMode? forcedMode = null)
    {
        InitializeComponent();
        _startMinimized = startMinimized;
        _config = AppConfig.Load();
        _forcedMode = forcedMode;
        _sync = new SyncController(_fileLog, _audit);
        _diagnostics = new Diagnostics(_sync);
        _tray = new TrayIcon(ShowFromTray, () => { ShowFromTray(); AutoFix_Click(this, new RoutedEventArgs()); }, ExitApp);

        LogList.ItemsSource = _log;
        _sync.Log += m => Dispatcher.BeginInvoke(() => AddLog(m));
        _sync.Changed += () => Dispatcher.BeginInvoke(ScheduleRefresh);
        _sync.TokenEvent += e => Dispatcher.BeginInvoke(() => OnTokenEvent(e));
        _audit.Written += _ => Dispatcher.BeginInvoke(() => { if (Tabs.SelectedIndex == 2) LoadReport(); });

        _uiDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _uiDebounce.Tick += (_, _) => { _uiDebounce.Stop(); RefreshTokenCard(); };
        _healthTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        _healthTimer.Tick += async (_, _) => await RefreshHealthAsync();

        ReportFrom.SelectedDate = DateTime.Today.AddDays(-7);
        ReportTo.SelectedDate = DateTime.Today;
        Tabs.SelectionChanged += (_, e) => { if (e.Source == Tabs && Tabs.SelectedIndex == 2) LoadReport(); };

        Loaded += async (_, _) => await OnLoadedAsync();
        Closing += OnClosing;
        SourceInitialized += (_, _) => UseDarkTitleBar();
    }

    private async Task OnLoadedAsync()
    {
        _loadingSettings = true;
        // First run on a Remote Desktop session defaults to Remote mode, on a physical PC to Local mode.
        if (!File.Exists(AppConfig.DefaultPath))
        {
            _config.Mode = WinNative.IsRemoteSession ? SyncMode.Remote : SyncMode.Local;
            _config.StartWithWindows = true;
            Installer.SetAutoStart(true);
            _config.Save();
        }
        if (_forcedMode is { } forced && forced != _config.Mode)
        {
            _config.Mode = forced;
            _config.Save();
        }
        (_config.Mode == SyncMode.Local ? ModeLocal : ModeRemote).IsChecked = true;
        LoadSettingsIntoForm();
        _loadingSettings = false;

        if (_startMinimized) Hide();
        await StartSyncAsync();
        _healthTimer.Start();
    }

    private async Task StartSyncAsync()
    {
        try
        {
            await _sync.StartAsync(_config);
        }
        catch (Exception ex)
        {
            AddLog("Failed to start: " + ex.Message);
            _fileLog.Write(ex.ToString());
        }
        SubtitleText.Text = _config.Mode == SyncMode.Local
            ? "Local PC — your USB DSC token is shared with your Remote Desktop session"
            : $"Remote Desktop — using the DSC token of your Local PC  (user {DscSync.Core.SessionInfo.UserName})";
        RefreshTokenCard();
        await RefreshHealthAsync();
    }

    // ------------------------------------------------------------------ token card & badge

    private void ScheduleRefresh()
    {
        _uiDebounce.Stop();
        _uiDebounce.Start();
    }

    private void OnTokenEvent(TokenEventDto e)
    {
        RefreshTokenCard();
        var cert = e.State.Tokens.FirstOrDefault()?.Certificates.FirstOrDefault();
        if (e.Kind == TokenEventKind.TokenInserted && cert is not null)
            _tray.Notify("DSC token ready", $"{cert.SubjectCommonName} ({e.State.Tokens[0].Vendor})");
        else if (e.Kind == TokenEventKind.TokenRemoved)
            _tray.Notify("DSC token removed", e.State.Tokens.Count == 0 ? "Insert a DSC token on the Local PC" : "Another token is still available", System.Windows.Forms.ToolTipIcon.Warning);
    }

    private void RefreshTokenCard()
    {
        var state = _sync.State;
        var token = state.Tokens.FirstOrDefault();
        var cert = token?.Certificates.FirstOrDefault();
        var link = _sync.Link;

        if (token is null || cert is null)
        {
            HolderText.Text = token is null ? "No token" : token.Label;
            OrgText.Text = _config.Mode == SyncMode.Local ? "Insert a USB DSC token into this PC" : "Insert the DSC token on your Local PC";
            VendorText.Text = token?.Vendor ?? "—";
            IssuerText.Text = ExpiryText.Text = SerialText.Text = CertSerialText.Text = "—";
            ExpiryText.Foreground = (Brush)FindResource("Text");
        }
        else
        {
            HolderText.Text = cert.SubjectCommonName;
            OrgText.Text = string.IsNullOrEmpty(cert.Organization) ? token.Label : cert.Organization;
            VendorText.Text = token.Vendor;
            IssuerText.Text = cert.IssuerCommonName;
            var days = (cert.NotAfter - DateTime.UtcNow).TotalDays;
            ExpiryText.Text = $"{cert.NotAfter.ToLocalTime():dd MMM yyyy}  ({(days < 0 ? "EXPIRED" : $"{days:F0} days left")})";
            ExpiryText.Foreground = (Brush)FindResource(days < 0 ? "Bad" : days < 30 ? "Warn" : "Ok");
            SerialText.Text = token.SerialNumber;
            CertSerialText.Text = cert.SerialNumber;
        }
        OtherTokensText.Text = state.Tokens.Count > 1
            ? "Also available: " + string.Join(", ", state.Tokens.Skip(1).Select(t => t.Certificates.FirstOrDefault()?.SubjectCommonName ?? t.Label))
            : "";

        string badge;
        Color color;
        if (link is null)
        {
            badge = token is null ? "NO TOKEN" : _config.Mode == SyncMode.Local ? "TOKEN READY • NOT LINKED" : "NOT LINKED";
            color = token is null ? Color.FromRgb(0xEF, 0x44, 0x44) : Color.FromRgb(0xF5, 0x9E, 0x0B);
        }
        else if (token is null)
        {
            badge = "LINKED • NO TOKEN";
            color = Color.FromRgb(0xF5, 0x9E, 0x0B);
        }
        else
        {
            badge = link.Transport == DscSync.Tunnel.Transports.TransportKinds.RdpDvc ? "SYNCED VIA RDP DVC" : "SYNCED VIA TLS TUNNEL";
            color = Color.FromRgb(0x22, 0xC5, 0x5E);
        }
        SyncBadgeText.Text = badge;
        SyncBadgeText.Foreground = new SolidColorBrush(color);
        SyncBadge.Background = new SolidColorBrush(Color.FromArgb(0x33, color.R, color.G, color.B));
        _tray.SetState(DrawingColor.FromArgb(color.R, color.G, color.B), badge);

        LinkText.Text = link is null ? "Not linked yet" : $"{link.Transport}  •  {link.Peer}  •  since {link.ConnectedUtc.ToLocalTime():HH:mm:ss}";
        LinkHint.Text = _config.Mode == SyncMode.Local
            ? "Connect to your cloud server with Remote Desktop (mstsc). DSC-Sync on the server links automatically through the RDP channel — no ports, no firewall changes."
              + (_sync.TlsPort > 0 ? "" : "")
            : "Keep DSC-Sync running on your Local PC (Local mode). GST / MCA / Income Tax portals and PDF signing on this server will use your token."
              + (_sync.TlsPort > 0 ? $"  TLS tunnel fallback port for your Local PC: {_sync.TlsPort}." : "");

        RefreshCertChoices();
    }

    // ------------------------------------------------------------------ health / diagnostics

    private async Task RefreshHealthAsync()
    {
        try
        {
            var items = await _diagnostics.CheckAsync();
            HealthList.ItemsSource = items;
            HealthTime.Text = "Updated " + DateTime.Now.ToString("HH:mm:ss");
        }
        catch (Exception ex) { AddLog("Health check failed: " + ex.Message); }
    }

    private async void AutoFix_Click(object sender, RoutedEventArgs e)
    {
        AutoFixButton.IsEnabled = false;
        FixReport.Text = "Running diagnostics…";
        try
        {
            FixReport.Text = await _diagnostics.AutoFixAsync(DiagPin.Password);
            DiagPin.Clear();
            await RefreshHealthAsync();
        }
        catch (Exception ex) { FixReport.Text = "Auto-fix failed: " + ex.Message; }
        finally { AutoFixButton.IsEnabled = true; }
    }

    private async void RefreshHealth_Click(object sender, RoutedEventArgs e) => await RefreshHealthAsync();

    private async void SupportBundle_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var items = await _diagnostics.CheckAsync();
            var path = _fileLog.ExportSupportBundle(_config, Diagnostics.Format(items));
            FixReport.Text = "Support bundle saved: " + path;
            Installer.OpenFolder(path);
        }
        catch (Exception ex) { FixReport.Text = "Could not create bundle: " + ex.Message; }
    }

    // ------------------------------------------------------------------ mode & settings

    private async void Mode_Checked(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;
        var mode = ModeLocal.IsChecked == true ? SyncMode.Local : SyncMode.Remote;
        if (mode == _config.Mode) return;
        _config.Mode = mode;
        _config.Save();
        await StartSyncAsync();
    }

    private void LoadSettingsIntoForm()
    {
        TransportCombo.SelectedIndex = (int)_config.Transport;
        HostBox.Text = _config.RemoteHost;
        PortBox.Text = _config.TunnelPort.ToString();
        PairPinBox.Password = _config.PairingPin;
        PortsBox.Text = string.Join(", ", _config.EmSignerPorts);
        AutoStartCheck.IsChecked = Installer.IsAutoStartEnabled();
        StopEmSignerCheck.IsChecked = _config.StopRemoteEmSigner;
        SyncCertCheck.IsChecked = _config.SyncEmSignerCertificate;
        SimulatedCheck.IsChecked = _config.UseSimulatedToken;
        VendorBox.Text = string.Join(Environment.NewLine, _config.VendorLibraries);
    }

    private async void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port is < 1024 or > 65535)
        {
            SettingsResult.Text = "Tunnel port must be between 1024 and 65535";
            return;
        }
        var ports = PortsBox.Text.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p, out var v) ? v : -1).ToList();
        if (ports.Count == 0 || ports.Any(p => p is < 1 or > 65535))
        {
            SettingsResult.Text = "emSigner ports must be comma-separated numbers";
            return;
        }
        if (PairPinBox.Password.Length is > 0 and < 4)
        {
            SettingsResult.Text = "Pairing PIN must have at least 4 characters";
            return;
        }
        _config.Transport = (TransportPreference)Math.Max(0, TransportCombo.SelectedIndex);
        _config.RemoteHost = HostBox.Text.Trim();
        _config.TunnelPort = port;
        _config.PairingPin = PairPinBox.Password;
        _config.EmSignerPorts = ports;
        _config.StopRemoteEmSigner = StopEmSignerCheck.IsChecked == true;
        _config.SyncEmSignerCertificate = SyncCertCheck.IsChecked == true;
        _config.UseSimulatedToken = SimulatedCheck.IsChecked == true;
        _config.VendorLibraries = VendorBox.Text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        _config.StartWithWindows = AutoStartCheck.IsChecked == true;
        Installer.SetAutoStart(_config.StartWithWindows);
        _config.Save();
        SettingsResult.Text = "Saved. Restarting sync…";
        await StartSyncAsync();
        SettingsResult.Text = "Saved and restarted at " + DateTime.Now.ToString("HH:mm:ss");
    }

    private void AllUsers_Click(object sender, RoutedEventArgs e) =>
        SettingsResult.Text = Installer.EnableForAllUsers()
            ? "DSC-Sync will start automatically for every user who signs in to this server."
            : "Cancelled or not permitted (administrator approval required).";

    private void InstallService_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_config.PairingPin) || string.IsNullOrWhiteSpace(_config.RemoteHost))
        {
            SettingsResult.Text = "The service uses the TLS tunnel: set Remote VM host and a pairing PIN first.";
            return;
        }
        try
        {
            var svcCfg = _config.Clone();
            svcCfg.Mode = SyncMode.Local;
            svcCfg.Save(DscSync.App.Program.ServiceConfigPath);
        }
        catch (Exception ex)
        {
            SettingsResult.Text = "Could not write service configuration: " + ex.Message;
            return;
        }
        SettingsResult.Text = Installer.InstallService()
            ? "Service installed. It starts with Windows (no sign-in needed)."
            : "Cancelled or failed (administrator approval required).";
    }

    private void RemoveService_Click(object sender, RoutedEventArgs e) =>
        SettingsResult.Text = Installer.UninstallService() ? "Service removed." : "Cancelled or not installed.";

    // ------------------------------------------------------------------ reports

    private static readonly HashSet<string> UsageOperations = new()
    {
        AuditOperations.Sign, AuditOperations.Login, AuditOperations.PdfSigned, AuditOperations.PortalActivity,
    };

    private IReadOnlyList<AuditEntry> QueryReport()
    {
        var from = ReportFrom.SelectedDate ?? DateTime.Today.AddDays(-7);
        var to = ReportTo.SelectedDate ?? DateTime.Today;
        if (to < from) (from, to) = (to, from);
        var rows = _audit.Query(from, to, ReportUser.Text, ReportSearch.Text);
        if (ReportKind.SelectedIndex == 0) rows = rows.Where(r => UsageOperations.Contains(r.Operation)).ToList();
        return rows;
    }

    private void LoadReport()
    {
        try
        {
            var rows = QueryReport();
            ReportGrid.ItemsSource = rows;
            StatSignatures.Text = rows.Count(r => r.Success && (r.Operation == AuditOperations.Sign || r.Operation == AuditOperations.PdfSigned)).ToString();
            StatPortal.Text = rows.Count(r => r.Operation == AuditOperations.PortalActivity).ToString();
            StatUsers.Text = rows.Select(r => r.User).Distinct(StringComparer.OrdinalIgnoreCase).Count().ToString();
            StatCerts.Text = rows.Where(r => r.TokenSerial.Length > 0).Select(r => r.TokenSerial).Distinct().Count().ToString();
        }
        catch (Exception ex) { AddLog("Report failed: " + ex.Message); }
    }

    private void ReportRefresh_Click(object sender, RoutedEventArgs e) => LoadReport();

    private void ReportToday_Click(object sender, RoutedEventArgs e)
    {
        ReportFrom.SelectedDate = ReportTo.SelectedDate = DateTime.Today;
        LoadReport();
    }

    private void ReportExport_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = "CSV (Excel)|*.csv",
            FileName = $"DSC-usage-{ReportFrom.SelectedDate:yyyyMMdd}-{ReportTo.SelectedDate:yyyyMMdd}.csv",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dlg.FileName, AuditLog.ToCsv(QueryReport()), new System.Text.UTF8Encoding(true));
            Installer.OpenFolder(dlg.FileName);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed"); }
    }

    // ------------------------------------------------------------------ PDF signer

    private void RefreshCertChoices()
    {
        var selected = (CertCombo.SelectedItem as CertChoice)?.Certificate.Thumbprint;
        var choices = _sync.State.Tokens.SelectMany(t => t.Certificates.Select(c => new CertChoice { Token = t, Certificate = c })).ToList();
        CertCombo.ItemsSource = choices;
        CertCombo.SelectedItem = choices.FirstOrDefault(c => c.Certificate.Thumbprint == selected) ?? choices.FirstOrDefault();
    }

    private void Pdf_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Pdf_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.FirstOrDefault(f => f.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase)) is { } pdf)
            await LoadPdfAsync(pdf);
    }

    private async void BrowsePdf_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "PDF documents|*.pdf" };
        if (dlg.ShowDialog(this) == true) await LoadPdfAsync(dlg.FileName);
    }

    private async Task LoadPdfAsync(string path)
    {
        try
        {
            _pdfPath = path;
            _pdfPages = PdfSigningService.GetPageCount(path);
            _pdfPage = _pdfPages;
            _sigRect = null;
            SigRect.Visibility = Visibility.Collapsed;
            PdfName.Text = Path.GetFileName(path);
            SignResult.Text = "";
            OpenSignedButton.Visibility = Visibility.Collapsed;
            await RenderPageAsync();
        }
        catch (Exception ex)
        {
            SignResult.Text = "Cannot open PDF: " + ex.Message;
        }
    }

    private async Task RenderPageAsync()
    {
        if (_pdfPath is null) return;
        _pageSize = PdfSigningService.GetPageSize(_pdfPath, _pdfPage);
        PageLabel.Text = $"Page {_pdfPage} / {_pdfPages}";
        DropHint.Visibility = Visibility.Collapsed;
        try
        {
            PageImage.Source = await PdfPreview.RenderAsync(_pdfPath, _pdfPage - 1, 620);
        }
        catch (Exception ex)
        {
            PageImage.Source = null;
            AddLog("Preview unavailable: " + ex.Message);
        }
        var w = PageImage.Source?.Width ?? 620;
        var h = PageImage.Source?.Height ?? 620 * _pageSize.H / Math.Max(1, _pageSize.W);
        PageCanvas.Width = w;
        PageCanvas.Height = h;
        UpdateRectText();
    }

    private async void PrevPage_Click(object sender, RoutedEventArgs e)
    {
        if (_pdfPath is null || _pdfPage <= 1) return;
        _pdfPage--;
        await RenderPageAsync();
    }

    private async void NextPage_Click(object sender, RoutedEventArgs e)
    {
        if (_pdfPath is null || _pdfPage >= _pdfPages) return;
        _pdfPage++;
        await RenderPageAsync();
    }

    private void Page_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (_pdfPath is null) return;
        _dragStart = e.GetPosition(PageCanvas);
        PageCanvas.CaptureMouse();
    }

    private void Page_MouseMove(object sender, MouseEventArgs e)
    {
        if (_dragStart is not { } start || e.LeftButton != MouseButtonState.Pressed) return;
        var p = e.GetPosition(PageCanvas);
        var r = new Rect(start, p);
        r.Intersect(new Rect(0, 0, PageCanvas.Width, PageCanvas.Height));
        if (r.IsEmpty) return;
        Canvas.SetLeft(SigRect, r.X);
        Canvas.SetTop(SigRect, r.Y);
        SigRect.Width = r.Width;
        SigRect.Height = r.Height;
        SigRect.Visibility = Visibility.Visible;
        _sigRect = r;
    }

    private void Page_MouseUp(object sender, MouseButtonEventArgs e)
    {
        PageCanvas.ReleaseMouseCapture();
        _dragStart = null;
        if (_sigRect is { } r && (r.Width < 20 || r.Height < 12))
        {
            // A click: place a default-size box centred on the click.
            var c = new Point(r.X, r.Y);
            r = new Rect(Math.Max(0, c.X - 80), Math.Max(0, c.Y - 28), 160, 56);
            Canvas.SetLeft(SigRect, r.X);
            Canvas.SetTop(SigRect, r.Y);
            SigRect.Width = r.Width;
            SigRect.Height = r.Height;
            SigRect.Visibility = Visibility.Visible;
            _sigRect = r;
        }
        UpdateRectText();
    }

    private PdfSignOptions BuildOptions()
    {
        var o = new PdfSignOptions
        {
            PageNumber = _pdfPage,
            Visible = VisibleCheck.IsChecked == true,
            Reason = ReasonBox.Text.Trim(),
            Location = LocationBox.Text.Trim(),
        };
        if (_sigRect is { } r && PageCanvas.Width > 0)
        {
            double sx = _pageSize.W / PageCanvas.Width, sy = _pageSize.H / PageCanvas.Height;
            o.X = (float)(r.X * sx);
            o.Width = (float)(r.Width * sx);
            o.Height = (float)(r.Height * sy);
            o.Y = (float)(_pageSize.H - (r.Y + r.Height) * sy);
        }
        else
        {
            o.X = Math.Max(10, _pageSize.W - 210);
            o.Y = 40;
        }
        return o;
    }

    private void UpdateRectText()
    {
        if (_pdfPath is null) return;
        var o = BuildOptions();
        RectText.Text = $"Page {o.PageNumber}: x={o.X:F0}, y={o.Y:F0}, {o.Width:F0}×{o.Height:F0} pt" + (_sigRect is null ? " (default — drag on the page to change)" : "");
    }

    private async void SignPdf_Click(object sender, RoutedEventArgs e)
    {
        if (_pdfPath is null) { SignResult.Text = "Choose a PDF first."; return; }
        if (CertCombo.SelectedItem is not CertChoice choice) { SignResult.Text = "No DSC certificate available. Insert the token on the Local PC."; return; }
        if (string.IsNullOrEmpty(PdfPin.Password)) { SignResult.Text = "Enter the token PIN."; return; }
        var client = _sync.Client;
        if (client is null) return;

        SignButton.IsEnabled = false;
        SignResult.Foreground = (Brush)FindResource("Text");
        SignResult.Text = "Signing… (the token may blink on the Local PC)";
        var input = _pdfPath;
        var output = Path.Combine(Path.GetDirectoryName(input)!, Path.GetFileNameWithoutExtension(input) + "_signed.pdf");
        for (int i = 2; File.Exists(output); i++)
            output = Path.Combine(Path.GetDirectoryName(input)!, $"{Path.GetFileNameWithoutExtension(input)}_signed({i}).pdf");
        var options = BuildOptions();
        var pin = PdfPin.Password;
        try
        {
            await client.LoginAsync(choice.Token.SlotId, _sync.State.Generation, pin);
            var result = await Task.Run(() =>
            {
                using var rsa = new TokenRsa(client, choice.Token, choice.Certificate);
                using var x509 = new X509Certificate2(choice.Certificate.Der);
                return PdfSigningService.Sign(input, output, x509, rsa, options);
            });
            _lastSigned = result.OutputPath;
            SignResult.Foreground = (Brush)FindResource("Ok");
            SignResult.Text = $"✔ Signed by {result.SignerName} on page {result.Page}\n{Path.GetFileName(result.OutputPath)}";
            OpenSignedButton.Visibility = Visibility.Visible;
            PdfPin.Clear();
            _audit.Write(new AuditEntry
            {
                Operation = AuditOperations.PdfSigned,
                CertificateHolder = choice.Certificate.SubjectCommonName,
                TokenSerial = choice.Token.SerialNumber,
                Issuer = choice.Certificate.IssuerCommonName,
                TokenPc = _sync.Link?.Peer ?? Environment.MachineName,
                Application = "DSC-Sync Quick PDF Signer",
                Detail = Path.GetFileName(result.OutputPath),
            });
        }
        catch (Exception ex)
        {
            SignResult.Foreground = (Brush)FindResource("Bad");
            var msg = ex is RpcException rpc && rpc.Code == DscSync.Core.Pkcs11.CKR.PIN_INCORRECT ? "Incorrect token PIN." : ex.GetBaseException().Message;
            SignResult.Text = "✖ " + msg;
            _audit.Write(new AuditEntry
            {
                Operation = AuditOperations.PdfSigned,
                CertificateHolder = choice.Certificate.SubjectCommonName,
                TokenSerial = choice.Token.SerialNumber,
                Application = "DSC-Sync Quick PDF Signer",
                Detail = Path.GetFileName(input) + ": " + msg,
                Success = false,
            });
        }
        finally { SignButton.IsEnabled = true; }
    }

    private void OpenSigned_Click(object sender, RoutedEventArgs e)
    {
        if (_lastSigned is not null) Installer.OpenFolder(_lastSigned);
    }

    // ------------------------------------------------------------------ log, tray, lifetime

    private void AddLog(string message)
    {
        _log.Insert(0, $"{DateTime.Now:HH:mm:ss}  {message}");
        while (_log.Count > 1000) _log.RemoveAt(_log.Count - 1);
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", _fileLog.Directory) { UseShellExecute = true });

    private void ClearLog_Click(object sender, RoutedEventArgs e) => _log.Clear();

    public void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_exiting) return;
        // Closing the window keeps the bridge running in the tray.
        e.Cancel = true;
        Hide();
        _tray.Notify("DSC-Sync is still running", "Signing keeps working. Right-click the tray icon to exit.");
    }

    private async void ExitApp()
    {
        _exiting = true;
        _healthTimer.Stop();
        try { await _sync.DisposeAsync(); } catch (Exception) { }
        _tray.Dispose();
        Application.Current.Shutdown();
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private void UseDarkTitleBar()
    {
        try
        {
            int on = 1;
            DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref on, sizeof(int));
        }
        catch (Exception) { }
    }
}
