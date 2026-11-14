using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DscSync.Core.Audit;

public static class AuditOperations
{
    public const string Login = "Token Login";
    public const string Sign = "Signature";
    public const string PdfSigned = "PDF Signed";
    public const string PortalActivity = "Portal Signing (emSigner)";
    public const string TokenInserted = "Token Inserted";
    public const string TokenRemoved = "Token Removed";
    public const string Linked = "Link Connected";
    public const string Unlinked = "Link Disconnected";
}

/// <summary>One "who used which DSC, when, for what" record.</summary>
public sealed class AuditEntry
{
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    /// <summary>Windows account that triggered the action (DOMAIN\user).</summary>
    public string User { get; set; } = SessionInfo.UserName;
    public string Machine { get; set; } = Environment.MachineName;
    public int Session { get; set; } = SessionInfo.CurrentSessionId;
    /// <summary>Local PC (token owner) as reported over the link.</summary>
    public string TokenPc { get; set; } = "";
    public string Operation { get; set; } = "";
    public string CertificateHolder { get; set; } = "";
    public string TokenSerial { get; set; } = "";
    public string Issuer { get; set; } = "";
    /// <summary>Application or portal, e.g. "AcroRd32.exe", "chrome.exe → emSigner :1585", "Quick PDF Signer".</summary>
    public string Application { get; set; } = "";
    public string Detail { get; set; } = "";
    public bool Success { get; set; } = true;

    [JsonIgnore] public DateTime LocalTime => TimestampUtc.ToLocalTime();
}

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(AuditEntry))]
public sealed partial class AuditJson : JsonSerializerContext { }

/// <summary>
/// Append-only audit store shared by every user on the machine. Each user writes only their own monthly file
/// (no cross-user write contention or permission problems); reports read all files.
/// Layout: {root}\{yyyy-MM}\{user}@{machine}.jsonl
/// </summary>
public sealed class AuditLog
{
    private readonly string _root;
    private readonly object _lock = new();

    public AuditLog(string? root = null) => _root = root ?? DefaultRoot;

    public static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), DscConstants.AppFolderName, "audit");

    public string Root => _root;

    public event Action<AuditEntry>? Written;

    public void Write(AuditEntry entry)
    {
        var line = JsonSerializer.Serialize(entry, AuditJson.Default.AuditEntry) + Environment.NewLine;
        var dir = Path.Combine(_root, entry.TimestampUtc.ToString("yyyy-MM", CultureInfo.InvariantCulture));
        var file = Path.Combine(dir, Sanitize($"{entry.User}@{entry.Machine}") + ".jsonl");
        lock (_lock)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    Directory.CreateDirectory(dir);
                    using var fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    var bytes = Encoding.UTF8.GetBytes(line);
                    fs.Write(bytes);
                    break;
                }
                catch (IOException) when (attempt < 4) { Thread.Sleep(20 * (attempt + 1)); }
                catch (UnauthorizedAccessException) { return; } // never let auditing break signing
                catch (IOException) { return; }
            }
        }
        try { Written?.Invoke(entry); } catch (Exception) { }
    }

    /// <summary>Reads all entries between the two local dates (inclusive), newest first.</summary>
    public IReadOnlyList<AuditEntry> Query(DateTime fromLocal, DateTime toLocal, string? userFilter = null, string? textFilter = null)
    {
        var fromUtc = fromLocal.Date.ToUniversalTime();
        var toUtc = toLocal.Date.AddDays(1).ToUniversalTime();
        var result = new List<AuditEntry>();
        if (!Directory.Exists(_root)) return result;
        for (var month = new DateTime(fromUtc.Year, fromUtc.Month, 1); month <= toUtc; month = month.AddMonths(1))
        {
            var dir = Path.Combine(_root, month.ToString("yyyy-MM", CultureInfo.InvariantCulture));
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.jsonl"))
            {
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(fs);
                    string? line;
                    while ((line = reader.ReadLine()) is not null)
                    {
                        if (line.Length == 0) continue;
                        AuditEntry? e;
                        try { e = JsonSerializer.Deserialize(line, AuditJson.Default.AuditEntry); }
                        catch (JsonException) { continue; } // tolerate a torn last line
                        if (e is null || e.TimestampUtc < fromUtc || e.TimestampUtc >= toUtc) continue;
                        if (!string.IsNullOrWhiteSpace(userFilter) && !e.User.Contains(userFilter, StringComparison.OrdinalIgnoreCase)) continue;
                        if (!string.IsNullOrWhiteSpace(textFilter) && !Matches(e, textFilter)) continue;
                        result.Add(e);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        result.Sort((a, b) => b.TimestampUtc.CompareTo(a.TimestampUtc));
        return result;
    }

    private static bool Matches(AuditEntry e, string text) =>
        e.CertificateHolder.Contains(text, StringComparison.OrdinalIgnoreCase)
        || e.TokenSerial.Contains(text, StringComparison.OrdinalIgnoreCase)
        || e.Operation.Contains(text, StringComparison.OrdinalIgnoreCase)
        || e.Application.Contains(text, StringComparison.OrdinalIgnoreCase)
        || e.Detail.Contains(text, StringComparison.OrdinalIgnoreCase)
        || e.TokenPc.Contains(text, StringComparison.OrdinalIgnoreCase);

    public static string ToCsv(IEnumerable<AuditEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Date,Time,User,Server,Session,Token PC,Operation,Certificate Holder,Token Serial,Issuer,Application,Result,Detail");
        foreach (var e in entries)
        {
            var t = e.LocalTime;
            sb.AppendJoin(',', new[]
            {
                t.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), t.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                e.User, e.Machine, e.Session.ToString(CultureInfo.InvariantCulture), e.TokenPc, e.Operation, e.CertificateHolder,
                e.TokenSerial, e.Issuer, e.Application, e.Success ? "OK" : "FAILED", e.Detail,
            }.Select(Csv));
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string Csv(string v)
    {
        v ??= "";
        // Neutralise spreadsheet formula injection and quote when needed.
        if (v.Length > 0 && "=+-@".Contains(v[0])) v = "'" + v;
        return v.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Replace('\\', '_');
    }
}
