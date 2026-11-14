using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DscSync.Core.Protocol;

namespace DscSync.Core.Pkcs11;

/// <summary>Transport used by the virtual PKCS#11 module to reach DSC-Sync (named pipe in production).</summary>
public interface IP11Channel : IDisposable
{
    /// <summary>Synchronous RPC. Throws <see cref="RpcException"/> on remote/transport errors.</summary>
    byte[]? Call(string method, byte[]? body, int timeoutMs);
}

public sealed class P11SlotInfo
{
    public string Description = "";
    public string Manufacturer = "";
    public ulong Flags;
}

public sealed class P11TokenInfo
{
    public string Label = "";
    public string Manufacturer = "";
    public string Model = "";
    public string Serial = "";
    public ulong Flags;
    public ulong MinPin;
    public ulong MaxPin;
    public ulong SessionCount;
    public ulong RwSessionCount;
}

public sealed class P11SessionInfo
{
    public ulong SlotId;
    public ulong State;
    public ulong Flags;
}

public readonly record struct P11Attribute(ulong Type, byte[] Value);

/// <summary>
/// Platform-neutral implementation of the PKCS#11 state machine exposed by DSC-Sync-P11.dll on the Remote VM.
/// Slots, objects and sessions mirror the token state of the Local PC; private-key operations are forwarded.
/// All public methods return CKR_* codes and are thread-safe.
/// </summary>
public sealed class VirtualP11Core : IDisposable
{
    public const string ManufacturerId = "DSC-Sync";
    public const string LibraryDescription = "DSC-Sync Remote Token Bridge";
    private const ulong KindCert = 1, KindPrivateKey = 2, KindPublicKey = 3;

    private readonly Func<IP11Channel> _channelFactory;
    private readonly int _ulongSize;
    private readonly object _lock = new();
    private readonly Dictionary<ulong, Session> _sessions = new();
    private readonly Dictionary<ulong, long> _loggedIn = new();      // virtual slot -> generation
    private readonly Dictionary<ulong, string> _pinCache = new();    // virtual slot -> PIN (memory only)
    private IP11Channel? _channel;
    private TokenStateDto _state = new();
    private long _stateFetchedTicks = long.MinValue;
    private long _lastReportedGeneration = -1;
    private ulong _nextSession = 1;
    private bool _initialized;
    private volatile bool _finalizing;

    public VirtualP11Core(Func<IP11Channel> channelFactory, int ulongSize)
    {
        _channelFactory = channelFactory;
        _ulongSize = ulongSize;
    }

    /// <summary>Minimum interval between token-state refreshes over the pipe.</summary>
    public int RefreshIntervalMs { get; set; } = 300;

    private sealed class Session
    {
        public ulong Handle;
        public ulong Slot;
        public long Generation;
        public ulong TokenSlotId;
        public bool ReadWrite;
        public List<ulong>? FindResults;
        public int FindIndex;
        public ulong SignMechanism;
        public PssParamsDto? SignPss;
        public ulong SignKey;
        public MemoryStream? SignBuffer;
        public bool SignActive;
    }

    // ---------------------------------------------------------------- lifecycle

    public ulong Initialize()
    {
        lock (_lock)
        {
            if (_initialized) return CKR.CRYPTOKI_ALREADY_INITIALIZED;
            _initialized = true;
            _finalizing = false;
            _stateFetchedTicks = long.MinValue;
            return CKR.OK;
        }
    }

    public ulong Finalize()
    {
        lock (_lock)
        {
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            _finalizing = true;
            _initialized = false;
            _sessions.Clear();
            _sessionTokenSerial.Clear();
            _loggedIn.Clear();
            _pinCache.Clear();
            _channel?.Dispose();
            _channel = null;
            return CKR.OK;
        }
    }

    public bool IsInitialized { get { lock (_lock) return _initialized; } }

    // ---------------------------------------------------------------- slots & tokens

    public ulong GetSlotList(bool tokenPresent, out ulong[] slots)
    {
        lock (_lock)
        {
            slots = Array.Empty<ulong>();
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            RefreshState(force: true);
            int count = Math.Max(1, _state.Tokens.Count);
            var list = new List<ulong>();
            for (int i = 0; i < count; i++)
            {
                if (tokenPresent && i >= _state.Tokens.Count) continue;
                list.Add((ulong)(i + 1));
            }
            slots = list.ToArray();
            return CKR.OK;
        }
    }

    public ulong GetSlotInfo(ulong slot, out P11SlotInfo info)
    {
        lock (_lock)
        {
            info = new P11SlotInfo();
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            RefreshState(force: false);
            if (slot < 1 || slot > (ulong)Math.Max(1, _state.Tokens.Count)) return CKR.SLOT_ID_INVALID;
            var token = TokenFor(slot);
            info.Description = token is null ? "DSC-Sync Remote Reader (no token)" : $"DSC-Sync Remote Reader - {token.Vendor}";
            info.Manufacturer = ManufacturerId;
            info.Flags = CKF.REMOVABLE_DEVICE | CKF.HW_SLOT | (token is null ? 0 : CKF.TOKEN_PRESENT);
            return CKR.OK;
        }
    }

    public ulong GetTokenInfo(ulong slot, out P11TokenInfo info)
    {
        lock (_lock)
        {
            info = new P11TokenInfo();
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            RefreshState(force: false);
            if (slot < 1 || slot > (ulong)Math.Max(1, _state.Tokens.Count)) return CKR.SLOT_ID_INVALID;
            var token = TokenFor(slot);
            if (token is null) return CKR.TOKEN_NOT_PRESENT;
            var cn = token.Certificates.FirstOrDefault()?.SubjectCommonName;
            info.Label = string.IsNullOrWhiteSpace(cn) ? token.Label : cn!;
            info.Manufacturer = string.IsNullOrWhiteSpace(token.Manufacturer) ? token.Vendor : token.Manufacturer;
            info.Model = token.Model;
            info.Serial = token.SerialNumber;
            info.Flags = CKF.LOGIN_REQUIRED | CKF.USER_PIN_INITIALIZED | CKF.TOKEN_INITIALIZED | CKF.WRITE_PROTECTED;
            info.MinPin = (ulong)Math.Max(1, token.MinPinLength);
            info.MaxPin = (ulong)Math.Max(token.MinPinLength, token.MaxPinLength);
            info.SessionCount = (ulong)_sessions.Values.Count(s => s.Slot == slot);
            info.RwSessionCount = (ulong)_sessions.Values.Count(s => s.Slot == slot && s.ReadWrite);
            return CKR.OK;
        }
    }

    public ulong GetMechanismList(ulong slot, out ulong[] mechanisms)
    {
        lock (_lock)
        {
            mechanisms = Array.Empty<ulong>();
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            RefreshState(force: false);
            if (slot < 1 || slot > (ulong)Math.Max(1, _state.Tokens.Count)) return CKR.SLOT_ID_INVALID;
            if (TokenFor(slot) is null) return CKR.TOKEN_NOT_PRESENT;
            mechanisms = CKM.Supported.ToArray();
            return CKR.OK;
        }
    }

    public ulong GetMechanismInfo(ulong slot, ulong mechanism, out ulong minKey, out ulong maxKey, out ulong flags)
    {
        minKey = maxKey = flags = 0;
        var rv = GetMechanismList(slot, out var list);
        if (rv != CKR.OK) return rv;
        if (!list.Contains(mechanism)) return CKR.MECHANISM_INVALID;
        minKey = 1024; maxKey = 4096; flags = CKF.HW | CKF.SIGN;
        return CKR.OK;
    }

    /// <summary>
    /// Implements C_WaitForSlotEvent. Returns CKR_NO_EVENT for non-blocking calls without a pending change.
    /// </summary>
    public ulong WaitForSlotEvent(bool dontBlock, out ulong slot)
    {
        slot = 0;
        if (!IsInitialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
        while (true)
        {
            long known;
            lock (_lock)
            {
                if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
                RefreshState(force: true);
                if (_lastReportedGeneration < 0) _lastReportedGeneration = _state.Generation;
                if (_state.Generation != _lastReportedGeneration)
                {
                    _lastReportedGeneration = _state.Generation;
                    slot = 1;
                    return CKR.OK;
                }
                if (dontBlock) return CKR.NO_EVENT;
                known = _state.Generation;
            }
            try
            {
                var body = ProtocolJson.Serialize(new WaitEventRequest { KnownGeneration = known, TimeoutMs = 5000 }, ProtocolJson.Default.WaitEventRequest);
                Channel().Call(RpcMethods.WaitEvent, body, 10_000);
            }
            catch (Exception)
            {
                if (_finalizing) return CKR.CRYPTOKI_NOT_INITIALIZED;
                Thread.Sleep(1000);
            }
            if (_finalizing) return CKR.CRYPTOKI_NOT_INITIALIZED;
            lock (_lock) _stateFetchedTicks = long.MinValue;
        }
    }

    // ---------------------------------------------------------------- sessions

    public ulong OpenSession(ulong slot, ulong flags, out ulong handle)
    {
        lock (_lock)
        {
            handle = 0;
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            if ((flags & CKF.SERIAL_SESSION) == 0) return CKR.SESSION_PARALLEL_NOT_SUPPORTED;
            RefreshState(force: true);
            if (slot < 1 || slot > (ulong)Math.Max(1, _state.Tokens.Count)) return CKR.SLOT_ID_INVALID;
            var token = TokenFor(slot);
            if (token is null) return CKR.TOKEN_NOT_PRESENT;
            var s = new Session
            {
                Handle = _nextSession++,
                Slot = slot,
                Generation = _state.Generation,
                TokenSlotId = token.SlotId,
                ReadWrite = (flags & CKF.RW_SESSION) != 0,
            };
            _sessions[s.Handle] = s;
            Remember(s, token);
            handle = s.Handle;
            return CKR.OK;
        }
    }

    public ulong CloseSession(ulong handle)
    {
        lock (_lock)
        {
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            if (!_sessions.Remove(handle, out var s)) return CKR.SESSION_HANDLE_INVALID;
            _sessionTokenSerial.Remove(handle);
            if (!_sessions.Values.Any(x => x.Slot == s.Slot))
            {
                _loggedIn.Remove(s.Slot);
                _pinCache.Remove(s.Slot);
            }
            return CKR.OK;
        }
    }

    public ulong CloseAllSessions(ulong slot)
    {
        lock (_lock)
        {
            if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
            foreach (var h in _sessions.Values.Where(s => s.Slot == slot).Select(s => s.Handle).ToList())
            {
                _sessions.Remove(h);
                _sessionTokenSerial.Remove(h);
            }
            _loggedIn.Remove(slot);
            _pinCache.Remove(slot);
            return CKR.OK;
        }
    }

    public ulong GetSessionInfo(ulong handle, out P11SessionInfo info)
    {
        lock (_lock)
        {
            info = new P11SessionInfo();
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            bool user = IsLoggedIn(s!);
            info.SlotId = s!.Slot;
            info.Flags = CKF.SERIAL_SESSION | (s.ReadWrite ? CKF.RW_SESSION : 0);
            info.State = s.ReadWrite
                ? (user ? CKS.RW_USER_FUNCTIONS : CKS.RW_PUBLIC_SESSION)
                : (user ? CKS.RO_USER_FUNCTIONS : CKS.RO_PUBLIC_SESSION);
            return CKR.OK;
        }
    }

    public ulong Login(ulong handle, ulong userType, string pin)
    {
        Session s;
        lock (_lock)
        {
            var rv = GetSession(handle, out var found);
            if (rv != CKR.OK) return rv;
            s = found!;
            if (userType == CKU.SO) return CKR.USER_TYPE_INVALID;
            if (userType != CKU.USER && userType != CKU.CONTEXT_SPECIFIC) return CKR.USER_TYPE_INVALID;
            if (userType == CKU.USER && IsLoggedIn(s)) return CKR.USER_ALREADY_LOGGED_IN;
        }
        try
        {
            var body = ProtocolJson.Serialize(new LoginRequest { SlotId = s.TokenSlotId, Generation = s.Generation, Pin = pin }, ProtocolJson.Default.LoginRequest);
            Channel().Call(RpcMethods.Login, body, 60_000);
        }
        catch (RpcException ex)
        {
            return MapError(ex);
        }
        lock (_lock)
        {
            _loggedIn[s.Slot] = s.Generation;
            _pinCache[s.Slot] = pin;
        }
        return CKR.OK;
    }

    public ulong Logout(ulong handle)
    {
        Session s;
        lock (_lock)
        {
            var rv = GetSession(handle, out var found);
            if (rv != CKR.OK) return rv;
            s = found!;
            if (!IsLoggedIn(s)) return CKR.USER_NOT_LOGGED_IN;
            _loggedIn.Remove(s.Slot);
            _pinCache.Remove(s.Slot);
        }
        try
        {
            Channel().Call(RpcMethods.Logout, ProtocolJson.Serialize(new SlotRequest { SlotId = s.TokenSlotId, Generation = s.Generation }, ProtocolJson.Default.SlotRequest), 15_000);
        }
        catch (RpcException) { /* local side may already be logged out after a hot-swap */ }
        return CKR.OK;
    }

    // ---------------------------------------------------------------- objects

    public ulong FindObjectsInit(ulong handle, IReadOnlyList<P11Attribute> template)
    {
        lock (_lock)
        {
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (s!.FindResults is not null) return CKR.OPERATION_ACTIVE;
            var token = TokenFor(s.Slot)!;
            var results = new List<ulong>();
            bool user = IsLoggedIn(s);
            for (int c = 0; c < token.Certificates.Count; c++)
            {
                foreach (var kind in new[] { KindCert, KindPublicKey, KindPrivateKey })
                {
                    if (kind == KindPrivateKey && (!user || !token.Certificates[c].HasPrivateKey)) continue;
                    ulong obj = MakeObjectHandle(s.Slot, c, kind);
                    var attrs = BuildAttributes(token.Certificates[c], kind);
                    if (template.All(t => attrs.TryGetValue(t.Type, out var v) && v.AsSpan().SequenceEqual(t.Value)))
                        results.Add(obj);
                }
            }
            s.FindResults = results;
            s.FindIndex = 0;
            return CKR.OK;
        }
    }

    public ulong FindObjects(ulong handle, int max, out ulong[] objects)
    {
        lock (_lock)
        {
            objects = Array.Empty<ulong>();
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (s!.FindResults is null) return CKR.OPERATION_NOT_INITIALIZED;
            int n = Math.Min(max, s.FindResults.Count - s.FindIndex);
            objects = s.FindResults.GetRange(s.FindIndex, Math.Max(0, n)).ToArray();
            s.FindIndex += objects.Length;
            return CKR.OK;
        }
    }

    public ulong FindObjectsFinal(ulong handle)
    {
        lock (_lock)
        {
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (s!.FindResults is null) return CKR.OPERATION_NOT_INITIALIZED;
            s.FindResults = null;
            return CKR.OK;
        }
    }

    /// <summary>Returns CKR_OK with the encoded value, CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID.</summary>
    public ulong GetAttributeValue(ulong handle, ulong obj, ulong type, out byte[]? value)
    {
        lock (_lock)
        {
            value = null;
            var rv = ResolveObject(handle, obj, out var cert, out var kind);
            if (rv != CKR.OK) return rv;
            if (kind == KindPrivateKey && type == CKA.VALUE) return CKR.ATTRIBUTE_SENSITIVE;
            var attrs = BuildAttributes(cert!, kind);
            if (!attrs.TryGetValue(type, out value)) return CKR.ATTRIBUTE_TYPE_INVALID;
            return CKR.OK;
        }
    }

    public ulong ValidateObject(ulong handle, ulong obj) { lock (_lock) return ResolveObject(handle, obj, out _, out _); }

    // ---------------------------------------------------------------- signing

    public ulong SignInit(ulong handle, ulong mechanism, PssParamsDto? pss, ulong key)
    {
        lock (_lock)
        {
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (s!.SignActive) return CKR.OPERATION_ACTIVE;
            if (!CKM.Supported.Contains(mechanism)) return CKR.MECHANISM_INVALID;
            if (CKM.IsPss(mechanism) && pss is null) return CKR.MECHANISM_PARAM_INVALID;
            rv = ResolveObject(handle, key, out _, out var kind);
            if (rv == CKR.OBJECT_HANDLE_INVALID) return CKR.KEY_HANDLE_INVALID;
            if (rv != CKR.OK) return rv;
            if (kind != KindPrivateKey) return CKR.KEY_TYPE_INCONSISTENT;
            if (!IsLoggedIn(s)) return CKR.USER_NOT_LOGGED_IN;
            s.SignActive = true;
            s.SignMechanism = mechanism;
            s.SignPss = pss;
            s.SignKey = key;
            s.SignBuffer = null;
            return CKR.OK;
        }
    }

    public ulong SignatureLength(ulong handle, out int length)
    {
        lock (_lock)
        {
            length = 0;
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (!s!.SignActive) return CKR.OPERATION_NOT_INITIALIZED;
            rv = ResolveObject(handle, s.SignKey, out var cert, out _);
            if (rv != CKR.OK) return rv;
            length = ModulusLength(cert!);
            return CKR.OK;
        }
    }

    public ulong SignUpdate(ulong handle, ReadOnlySpan<byte> part)
    {
        lock (_lock)
        {
            var rv = GetSession(handle, out var s);
            if (rv != CKR.OK) return rv;
            if (!s!.SignActive) return CKR.OPERATION_NOT_INITIALIZED;
            if (!CKM.IsHashing(s.SignMechanism)) { EndSign(s); return CKR.FUNCTION_NOT_SUPPORTED; }
            s.SignBuffer ??= new MemoryStream();
            s.SignBuffer.Write(part);
            return CKR.OK;
        }
    }

    /// <summary>Single-part sign (C_Sign) when <paramref name="data"/> is non-null, otherwise C_SignFinal.</summary>
    public ulong Sign(ulong handle, byte[]? data, out byte[] signature)
    {
        signature = Array.Empty<byte>();
        Session s;
        SignRequest request;
        lock (_lock)
        {
            var rv = GetSession(handle, out var found);
            if (rv != CKR.OK) return rv;
            s = found!;
            if (!s.SignActive) return CKR.OPERATION_NOT_INITIALIZED;
            rv = ResolveObject(handle, s.SignKey, out var cert, out _);
            if (rv != CKR.OK) { EndSign(s); return rv; }
            byte[] payload = data ?? s.SignBuffer?.ToArray() ?? Array.Empty<byte>();
            if (data is not null && s.SignBuffer is not null) { EndSign(s); return CKR.OPERATION_ACTIVE; }
            if (s.SignMechanism == CKM.RSA_PKCS && payload.Length > ModulusLength(cert!) - 11) { EndSign(s); return CKR.DATA_LEN_RANGE; }
            request = new SignRequest
            {
                SlotId = s.TokenSlotId,
                Generation = s.Generation,
                KeyId = cert!.Id,
                Mechanism = s.SignMechanism,
                Pss = s.SignPss,
                Data = payload,
            };
            EndSign(s);
        }

        try
        {
            signature = CallSign(request);
            return CKR.OK;
        }
        catch (RpcException ex) when (ex.Code == CKR.USER_NOT_LOGGED_IN && TryRelogin(s))
        {
            try
            {
                signature = CallSign(request);
                return CKR.OK;
            }
            catch (RpcException retry) { return MapError(retry); }
        }
        catch (RpcException ex)
        {
            return MapError(ex);
        }
    }

    private byte[] CallSign(SignRequest request)
    {
        var body = Channel().Call(RpcMethods.Sign, ProtocolJson.Serialize(request, ProtocolJson.Default.SignRequest), 120_000)
                   ?? throw new RpcException(CKR.FUNCTION_FAILED, "Empty sign response");
        return ProtocolJson.Deserialize(body, ProtocolJson.Default.SignResponse).Signature;
    }

    private bool TryRelogin(Session s)
    {
        string? pin;
        lock (_lock) _pinCache.TryGetValue(s.Slot, out pin);
        if (pin is null) return false;
        try
        {
            Channel().Call(RpcMethods.Login, ProtocolJson.Serialize(new LoginRequest { SlotId = s.TokenSlotId, Generation = s.Generation, Pin = pin }, ProtocolJson.Default.LoginRequest), 60_000);
            return true;
        }
        catch (RpcException) { return false; }
    }

    // ---------------------------------------------------------------- helpers

    private static void EndSign(Session s)
    {
        s.SignActive = false;
        s.SignBuffer?.Dispose();
        s.SignBuffer = null;
        s.SignPss = null;
    }

    private IP11Channel Channel()
    {
        lock (_lock) return _channel ??= _channelFactory();
    }

    private void RefreshState(bool force)
    {
        long now = Environment.TickCount64;
        if (!force && _stateFetchedTicks != long.MinValue && now - _stateFetchedTicks < RefreshIntervalMs) return;
        if (force && _stateFetchedTicks != long.MinValue && now - _stateFetchedTicks < 50) return;
        try
        {
            var body = (_channel ??= _channelFactory()).Call(RpcMethods.GetTokenState, null, 5000);
            _state = body is null ? new TokenStateDto() : ProtocolJson.Deserialize(body, ProtocolJson.Default.TokenStateDto);
            if (_lastReportedGeneration < 0) _lastReportedGeneration = _state.Generation;
        }
        catch (Exception)
        {
            // Pipe down or tunnel disconnected: behave like an empty reader instead of failing the host application.
            _channel?.Dispose();
            _channel = null;
            if (_state.Tokens.Count > 0) _state = new TokenStateDto { Generation = _state.Generation + 1 };
        }
        _stateFetchedTicks = now;
    }

    private TokenInfoDto? TokenFor(ulong slot)
    {
        int idx = (int)slot - 1;
        return idx >= 0 && idx < _state.Tokens.Count ? _state.Tokens[idx] : null;
    }

    private bool IsLoggedIn(Session s) => _loggedIn.TryGetValue(s.Slot, out var g) && g == s.Generation;

    private ulong GetSession(ulong handle, out Session? s)
    {
        s = null;
        if (!_initialized) return CKR.CRYPTOKI_NOT_INITIALIZED;
        if (!_sessions.TryGetValue(handle, out s)) return CKR.SESSION_HANDLE_INVALID;
        RefreshState(force: false);
        if (_state.Generation != s.Generation)
        {
            // The physical token was swapped/removed on the Local PC: the session is gone.
            var current = TokenFor(s.Slot);
            bool sameToken = current is not null && current.SlotId == s.TokenSlotId && TokenFingerprintMatches(s, current);
            if (!sameToken)
            {
                _sessions.Remove(handle);
                _sessionTokenSerial.Remove(handle);
                _loggedIn.Remove(s.Slot);
                _pinCache.Remove(s.Slot);
                return current is null ? CKR.DEVICE_REMOVED : CKR.SESSION_HANDLE_INVALID;
            }
            s.Generation = _state.Generation;
            if (_loggedIn.ContainsKey(s.Slot)) _loggedIn[s.Slot] = _state.Generation;
        }
        return CKR.OK;
    }

    private readonly Dictionary<ulong, string> _sessionTokenSerial = new();

    private bool TokenFingerprintMatches(Session s, TokenInfoDto current)
    {
        // Same local slot id and same serial => token was not swapped (e.g. another reader changed).
        if (!_sessionTokenSerial.TryGetValue(s.Handle, out var serial))
            return false;
        return serial == current.SerialNumber;
    }

    /// <summary>Records the token serial for a session so that unrelated generation bumps don't kill it.</summary>
    private void Remember(Session s, TokenInfoDto t) => _sessionTokenSerial[s.Handle] = t.SerialNumber;

    private ulong ResolveObject(ulong handle, ulong obj, out CertificateDto? cert, out ulong kind)
    {
        cert = null;
        kind = obj & 0xF;
        var rv = GetSession(handle, out var s);
        if (rv != CKR.OK) return rv;
        ulong slot = obj >> 24;
        int index = (int)((obj >> 4) & 0xFFFFF);
        if (slot != s!.Slot || kind is < KindCert or > KindPublicKey) return CKR.OBJECT_HANDLE_INVALID;
        var token = TokenFor(slot);
        if (token is null) return CKR.DEVICE_REMOVED;
        if (index >= token.Certificates.Count) return CKR.OBJECT_HANDLE_INVALID;
        cert = token.Certificates[index];
        if (kind == KindPrivateKey && !IsLoggedIn(s)) return CKR.OBJECT_HANDLE_INVALID;
        return CKR.OK;
    }

    private static ulong MakeObjectHandle(ulong slot, int certIndex, ulong kind) => (slot << 24) | ((ulong)certIndex << 4) | kind;

    private static int ModulusLength(CertificateDto c)
    {
        int len = c.Modulus.Length;
        if (len > 0 && c.Modulus[0] == 0) len--;
        return len > 0 ? len : Math.Max(128, c.KeySizeBits / 8);
    }

    private byte[] U(ulong v)
    {
        var b = new byte[_ulongSize];
        if (_ulongSize == 4) BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v);
        else BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        return b;
    }

    private static byte[] B(bool v) => new[] { v ? (byte)1 : (byte)0 };

    private Dictionary<ulong, byte[]> BuildAttributes(CertificateDto c, ulong kind)
    {
        var label = Encoding.UTF8.GetBytes(string.IsNullOrEmpty(c.Label) ? c.SubjectCommonName : c.Label);
        var a = new Dictionary<ulong, byte[]>
        {
            [CKA.TOKEN] = B(true),
            [CKA.LABEL] = label,
            [CKA.ID] = c.Id,
            [CKA.MODIFIABLE] = B(false),
        };
        byte[] subject = Array.Empty<byte>(), issuer = Array.Empty<byte>(), serial = Array.Empty<byte>();
        if (c.Der.Length > 0)
        {
            using var x = new X509Certificate2(c.Der);
            subject = x.SubjectName.RawData;
            issuer = x.IssuerName.RawData;
            var w = new AsnWriter(AsnEncodingRules.DER);
            w.WriteInteger(x.SerialNumberBytes.Span);
            serial = w.Encode();
        }
        switch (kind)
        {
            case KindCert:
                a[CKA.CLASS] = U(CKO.CERTIFICATE);
                a[CKA.PRIVATE] = B(false);
                a[CKA.CERTIFICATE_TYPE] = U(CKC.X_509);
                a[CKA.TRUSTED] = B(false);
                a[CKA.CERTIFICATE_CATEGORY] = U(1);
                a[CKA.VALUE] = c.Der;
                a[CKA.SUBJECT] = subject;
                a[CKA.ISSUER] = issuer;
                a[CKA.SERIAL_NUMBER] = serial;
                break;
            case KindPublicKey:
                a[CKA.CLASS] = U(CKO.PUBLIC_KEY);
                a[CKA.PRIVATE] = B(false);
                a[CKA.KEY_TYPE] = U(CKK.RSA);
                a[CKA.SUBJECT] = subject;
                a[CKA.MODULUS] = c.Modulus;
                a[CKA.MODULUS_BITS] = U((ulong)c.KeySizeBits);
                a[CKA.PUBLIC_EXPONENT] = c.PublicExponent;
                a[CKA.VERIFY] = B(true);
                a[CKA.ENCRYPT] = B(false);
                a[CKA.WRAP] = B(false);
                a[CKA.LOCAL] = B(true);
                break;
            case KindPrivateKey:
                a[CKA.CLASS] = U(CKO.PRIVATE_KEY);
                a[CKA.PRIVATE] = B(true);
                a[CKA.KEY_TYPE] = U(CKK.RSA);
                a[CKA.SUBJECT] = subject;
                a[CKA.MODULUS] = c.Modulus;
                a[CKA.PUBLIC_EXPONENT] = c.PublicExponent;
                a[CKA.SIGN] = B(true);
                a[CKA.SIGN_RECOVER] = B(false);
                a[CKA.DECRYPT] = B(false);
                a[CKA.UNWRAP] = B(false);
                a[CKA.DERIVE] = B(false);
                a[CKA.SENSITIVE] = B(true);
                a[CKA.ALWAYS_SENSITIVE] = B(true);
                a[CKA.EXTRACTABLE] = B(false);
                a[CKA.NEVER_EXTRACTABLE] = B(true);
                a[CKA.ALWAYS_AUTHENTICATE] = B(false);
                a[CKA.LOCAL] = B(true);
                break;
        }
        return a;
    }

    private static ulong MapError(RpcException ex) => ex.Code switch
    {
        RpcErrors.NotConnected or RpcErrors.Timeout => CKR.DEVICE_REMOVED,
        RpcErrors.Internal or RpcErrors.UnknownMethod => CKR.FUNCTION_FAILED,
        _ => ex.Code,
    };

    public void Dispose()
    {
        lock (_lock)
        {
            _channel?.Dispose();
            _channel = null;
        }
    }
}
