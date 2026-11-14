using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace DscSync.App.Services;

/// <summary>System tray presence with a generated icon (blue = linked, gold = waiting, red = no token).</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _status;
    private Icon? _current;

    public TrayIcon(Action open, Action autoFix, Action exit)
    {
        _status = new ToolStripMenuItem("Starting…") { Enabled = false };
        var menu = new ContextMenuStrip();
        menu.Items.Add(_status);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open DSC-Sync", null, (_, _) => open());
        menu.Items.Add("Diagnose && Auto-Fix", null, (_, _) => autoFix());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => exit());
        _icon = new NotifyIcon { ContextMenuStrip = menu, Visible = true, Text = "DSC-Sync" };
        _icon.DoubleClick += (_, _) => open();
        SetState(Color.FromArgb(0xF5, 0x9E, 0x0B), "Starting…");
    }

    public static Icon CreateIcon(Color accent)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var path = new GraphicsPath();
            path.AddArc(1, 1, 10, 10, 180, 90);
            path.AddArc(21, 1, 10, 10, 270, 90);
            path.AddArc(21, 21, 10, 10, 0, 90);
            path.AddArc(1, 21, 10, 10, 90, 90);
            path.CloseFigure();
            using var bg = new SolidBrush(Color.FromArgb(0x0F, 0x17, 0x2A));
            g.FillPath(bg, path);
            using var pen = new Pen(accent, 2.5f);
            g.DrawPath(pen, path);
            using var font = new Font("Segoe UI", 13, System.Drawing.FontStyle.Bold, GraphicsUnit.Pixel);
            using var text = new SolidBrush(accent);
            var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("DS", font, text, new RectangleF(0, 0, 32, 32), sf);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }

    public void SetState(Color accent, string status)
    {
        var old = _current;
        _current = CreateIcon(accent);
        _icon.Icon = _current;
        var tip = "DSC-Sync — " + status;
        _icon.Text = tip.Length > 63 ? tip[..63] : tip;
        _status.Text = status;
        if (old is not null) DestroyIcon(old.Handle);
        old?.Dispose();
    }

    public void Notify(string title, string text, ToolTipIcon kind = ToolTipIcon.Info) =>
        _icon.ShowBalloonTip(3000, title, text, kind);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        if (_current is not null) DestroyIcon(_current.Handle);
        _current?.Dispose();
    }
}
