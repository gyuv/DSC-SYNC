using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge.Backends;

namespace DscSync.Pkcs11Bridge;

/// <summary>Uniform token access for the PDF signer / diagnostics, regardless of Local or Remote mode.</summary>
public interface ITokenClient
{
    TokenStateDto State { get; }
    bool IsConnected { get; }
    event Action<TokenEventDto>? TokenEvent;
    Task LoginAsync(ulong slotId, long generation, string pin, CancellationToken ct = default);
    Task<byte[]> SignAsync(SignRequest request, CancellationToken ct = default);
}

/// <summary>
/// Owns the token backend on the Local PC. Serializes all PKCS#11 access, detects insert/remove by diffing scans
/// and raises <see cref="TokenEvent"/> (TOKEN_INSERTED / TOKEN_REMOVED) with a new generation number.
/// </summary>
public sealed class TokenManager : ITokenClient, IDisposable
{
    private readonly ITokenBackend _backend;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private TokenStateDto _state = new() { Generation = 1, TimestampUtc = DateTime.UtcNow };
    private string _fingerprint = "";
    private int _rescanRequested;
    private int _reloadRequested;
    private Task? _pollTask;

    public TokenManager(ITokenBackend backend) => _backend = backend;

    public ITokenBackend Backend => _backend;
    public TokenStateDto State => Volatile.Read(ref _state);
    public bool IsConnected => true;
    public TimeSpan Debounce { get; set; } = TimeSpan.FromMilliseconds(150);

    public event Action<TokenEventDto>? TokenEvent;
    public event Action<string>? Log;

    /// <summary>Synchronously rescans. <paramref name="reload"/> fully unloads and reloads vendor middleware.</summary>
    public TokenEventDto? Rescan(bool reload)
    {
        _gate.Wait();
        try
        {
            return RescanLocked(reload);
        }
        finally
        {
            _gate.Release();
        }
    }

    private TokenEventDto? RescanLocked(bool reload)
    {
        if (reload)
        {
            try { _backend.Reload(); }
            catch (Exception ex) { Log?.Invoke("Middleware reload failed: " + ex.Message); }
        }
        IReadOnlyList<TokenInfoDto> tokens;
        try { tokens = _backend.Enumerate(); }
        catch (Exception ex)
        {
            Log?.Invoke("Token scan failed: " + ex.Message);
            tokens = Array.Empty<TokenInfoDto>();
        }
        var fp = Fingerprint(tokens);
        if (fp == _fingerprint) return null;

        var old = _state;
        var oldSerials = old.Tokens.Select(t => t.SerialNumber).ToHashSet();
        var newSerials = tokens.Select(t => t.SerialNumber).ToHashSet();
        var state = new TokenStateDto { Generation = old.Generation + 1, TimestampUtc = DateTime.UtcNow, Tokens = tokens.ToList() };
        var ev = new TokenEventDto
        {
            State = state,
            AddedSerials = newSerials.Except(oldSerials).ToList(),
            RemovedSerials = oldSerials.Except(newSerials).ToList(),
        };
        ev.Kind = ev.AddedSerials.Count > 0 ? TokenEventKind.TokenInserted
            : ev.RemovedSerials.Count > 0 ? TokenEventKind.TokenRemoved
            : TokenEventKind.TokenChanged;
        _fingerprint = fp;
        Volatile.Write(ref _state, state);
        foreach (var s in ev.RemovedSerials) Log?.Invoke($"TOKEN_REMOVED serial={s}");
        foreach (var t in tokens.Where(t => ev.AddedSerials.Contains(t.SerialNumber)))
            Log?.Invoke($"TOKEN_INSERTED serial={t.SerialNumber} vendor={t.Vendor} cn={t.Certificates.FirstOrDefault()?.SubjectCommonName}");
        try { TokenEvent?.Invoke(ev); } catch (Exception ex) { Log?.Invoke("Token event handler failed: " + ex.Message); }
        return ev;
    }

    private static string Fingerprint(IEnumerable<TokenInfoDto> tokens) =>
        string.Join("|", tokens.OrderBy(t => t.SlotId).Select(t =>
            $"{t.SlotId}:{t.Vendor}:{t.SerialNumber}:{string.Join(",", t.Certificates.Select(c => c.Thumbprint))}"));

    /// <summary>Debounced asynchronous rescan, called from WM_DEVICECHANGE handlers.</summary>
    public void RequestRescan(bool reload)
    {
        if (reload) Interlocked.Exchange(ref _reloadRequested, 1);
        if (Interlocked.Exchange(ref _rescanRequested, 1) == 1) return;
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(Debounce, _cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            Interlocked.Exchange(ref _rescanRequested, 0);
            bool doReload = Interlocked.Exchange(ref _reloadRequested, 0) == 1;
            var ev = Rescan(doReload);
            // Some middleware only notices a different vendor's token after re-initialisation.
            if (ev is null && !doReload) Rescan(reload: true);
        });
    }

    /// <summary>Periodic safety-net scan in case a device notification was missed (or not available).</summary>
    public void StartPolling(TimeSpan interval)
    {
        _pollTask ??= Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try { await Task.Delay(interval, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                Rescan(reload: false);
            }
        });
    }

    public Task LoginAsync(ulong slotId, long generation, string pin, CancellationToken ct = default) =>
        RunLockedAsync(() => { EnsureSlot(slotId); _backend.Login(slotId, pin); return 0; }, ct);

    public Task LogoutAsync(ulong slotId, CancellationToken ct = default) =>
        RunLockedAsync(() => { _backend.Logout(slotId); return 0; }, ct);

    public Task<byte[]> SignAsync(SignRequest r, CancellationToken ct = default) =>
        RunLockedAsync(() =>
        {
            EnsureSlot(r.SlotId);
            return _backend.Sign(r.SlotId, r.KeyId, r.Mechanism, r.Pss, r.Data);
        }, ct);

    private void EnsureSlot(ulong slotId)
    {
        if (State.Tokens.All(t => t.SlotId != slotId))
            throw new RpcException(CKR.DEVICE_REMOVED, "The selected DSC token was removed from the Local PC");
    }

    private async Task<T> RunLockedAsync<T>(Func<T> op, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await Task.Run(op, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _gate.Wait();
        try { _backend.Dispose(); }
        finally { _gate.Release(); }
    }
}
