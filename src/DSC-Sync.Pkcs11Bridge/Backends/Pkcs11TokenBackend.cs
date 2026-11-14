using DscSync.Core.Protocol;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using P11CKA = Net.Pkcs11Interop.Common.CKA;
using P11CKO = Net.Pkcs11Interop.Common.CKO;
using P11CKU = Net.Pkcs11Interop.Common.CKU;
using P11CKR = Net.Pkcs11Interop.Common.CKR;

namespace DscSync.Pkcs11Bridge.Backends;

/// <summary>
/// Real hardware backend: loads the vendor PKCS#11 middleware(s) through Pkcs11Interop. Slot ids exposed to the
/// rest of DSC-Sync are composite: (library index + 1) &lt;&lt; 32 | vendor slot id.
/// </summary>
public sealed class Pkcs11TokenBackend : ITokenBackend
{
    private readonly Func<IReadOnlyList<(string Path, string Vendor)>> _discover;
    private readonly Pkcs11InteropFactories _factories = new();
    private readonly List<LoadedLibrary> _libraries = new();
    private readonly Dictionary<ulong, ISession> _userSessions = new();
    private bool _loaded;

    public Pkcs11TokenBackend(Func<IReadOnlyList<(string Path, string Vendor)>> discover) => _discover = discover;

    public string Name => "PKCS#11 (" + (_libraries.Count == 0 ? "no vendor library" : string.Join(", ", _libraries.Select(l => l.Vendor))) + ")";

    public event Action<string>? Log;

    public IReadOnlyList<string> LoadedLibraries => _libraries.Select(l => l.Path).ToList();

    private sealed class LoadedLibrary
    {
        public required string Path;
        public required string Vendor;
        public required IPkcs11Library Library;
    }

    public void Reload()
    {
        UnloadAll();
        foreach (var (path, vendor) in _discover())
        {
            try
            {
                var lib = _factories.Pkcs11LibraryFactory.LoadPkcs11Library(_factories, path, AppType.MultiThreaded);
                _libraries.Add(new LoadedLibrary { Path = path, Vendor = vendor, Library = lib });
                Log?.Invoke($"Loaded {vendor} middleware: {path}");
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Could not load {path}: {ex.Message}");
            }
        }
        _loaded = true;
    }

    public IReadOnlyList<TokenInfoDto> Enumerate()
    {
        if (!_loaded) Reload();
        var tokens = new List<TokenInfoDto>();
        for (int li = 0; li < _libraries.Count; li++)
        {
            var lib = _libraries[li];
            List<ISlot> slots;
            try { slots = lib.Library.GetSlotList(SlotsType.WithTokenPresent); }
            catch (Pkcs11Exception ex)
            {
                Log?.Invoke($"{lib.Vendor}: C_GetSlotList failed ({ex.RV})");
                continue;
            }
            foreach (var slot in slots)
            {
                ulong compositeId = ((ulong)(li + 1) << 32) | (slot.SlotId & 0xFFFFFFFF);
                try
                {
                    tokens.Add(ReadToken(lib, slot, compositeId));
                }
                catch (Pkcs11Exception ex) when (ex.RV is P11CKR.CKR_TOKEN_NOT_PRESENT or P11CKR.CKR_DEVICE_REMOVED or P11CKR.CKR_SESSION_HANDLE_INVALID)
                {
                    DropSession(compositeId); // pulled out while we were reading it
                }
                catch (Exception ex)
                {
                    Log?.Invoke($"{lib.Vendor} slot {slot.SlotId}: {ex.Message}");
                }
            }
        }
        // Drop logged-in sessions whose token disappeared.
        foreach (var id in _userSessions.Keys.Where(k => tokens.All(t => t.SlotId != k)).ToList()) DropSession(id);
        return tokens;
    }

    private TokenInfoDto ReadToken(LoadedLibrary lib, ISlot slot, ulong compositeId)
    {
        var ti = slot.GetTokenInfo();
        var token = new TokenInfoDto
        {
            SlotId = compositeId,
            Vendor = lib.Vendor,
            LibraryPath = lib.Path,
            Label = ti.Label.Trim(),
            Model = ti.Model.Trim(),
            Manufacturer = ti.ManufacturerId.Trim(),
            SerialNumber = ti.SerialNumber.Trim(),
            MinPinLength = (int)Math.Min(ti.MinPinLen, 64),
            MaxPinLength = (int)Math.Min(ti.MaxPinLen, 64),
        };

        bool ownsSession = !_userSessions.TryGetValue(compositeId, out var session);
        session ??= slot.OpenSession(SessionType.ReadOnly);
        try
        {
            var template = new List<IObjectAttribute> { _factories.ObjectAttributeFactory.Create(P11CKA.CKA_CLASS, P11CKO.CKO_CERTIFICATE) };
            foreach (var obj in session.FindAllObjects(template))
            {
                var attrs = session.GetAttributeValue(obj, new List<P11CKA> { P11CKA.CKA_VALUE, P11CKA.CKA_ID, P11CKA.CKA_LABEL });
                var der = attrs[0].GetValueAsByteArray();
                if (der is null || der.Length == 0) continue;
                var id = attrs[1].GetValueAsByteArray() ?? Array.Empty<byte>();
                string label = attrs[2].GetValueAsString() ?? "";
                if (id.Length == 0 || !CertificateMetadata.IsSigningCertificate(der)) continue; // CA certs without key
                token.Certificates.Add(CertificateMetadata.FromDer(der, id, label, hasPrivateKey: true));
            }
        }
        finally
        {
            if (ownsSession) session.Dispose();
        }
        return token;
    }

    private (LoadedLibrary Lib, ISlot Slot) Resolve(ulong compositeId)
    {
        int li = (int)(compositeId >> 32) - 1;
        ulong vendorSlot = compositeId & 0xFFFFFFFF;
        if (li < 0 || li >= _libraries.Count) throw new RpcException(CoreCkr.SLOT_ID_INVALID, "Unknown slot");
        var lib = _libraries[li];
        var slot = lib.Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault(s => s.SlotId == vendorSlot)
                   ?? throw new RpcException(CoreCkr.TOKEN_NOT_PRESENT, "Token not present");
        return (lib, slot);
    }

    public void Login(ulong slotId, string pin)
    {
        Guard(() =>
        {
            DropSession(slotId);
            var (_, slot) = Resolve(slotId);
            var session = slot.OpenSession(SessionType.ReadOnly);
            try
            {
                session.Login(P11CKU.CKU_USER, pin);
            }
            catch (Pkcs11Exception ex) when (ex.RV == P11CKR.CKR_USER_ALREADY_LOGGED_IN)
            {
                // another application on the Local PC already logged in: fine
            }
            catch
            {
                session.Dispose();
                throw;
            }
            _userSessions[slotId] = session;
        });
    }

    public void Logout(ulong slotId)
    {
        Guard(() =>
        {
            if (_userSessions.TryGetValue(slotId, out var s))
            {
                try { s.Logout(); } catch (Pkcs11Exception) { }
                DropSession(slotId);
            }
        });
    }

    public byte[] Sign(ulong slotId, byte[] keyId, ulong mechanism, PssParamsDto? pss, byte[] data)
    {
        byte[] result = Array.Empty<byte>();
        Guard(() =>
        {
            if (!_userSessions.TryGetValue(slotId, out var session))
                throw new RpcException(CoreCkr.USER_NOT_LOGGED_IN, "Token PIN required");
            var template = new List<IObjectAttribute>
            {
                _factories.ObjectAttributeFactory.Create(P11CKA.CKA_CLASS, P11CKO.CKO_PRIVATE_KEY),
                _factories.ObjectAttributeFactory.Create(P11CKA.CKA_ID, keyId),
            };
            var key = session.FindAllObjects(template).FirstOrDefault()
                      ?? throw new RpcException(CoreCkr.KEY_HANDLE_INVALID, "Private key for this certificate was not found on the token");
            IMechanism mech = pss is null
                ? _factories.MechanismFactory.Create(mechanism)
                : _factories.MechanismFactory.Create(mechanism, _factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(pss.HashAlg, pss.Mgf, pss.SaltLength));
            result = session.Sign(mech, key, data);
        });
        return result;
    }

    private void Guard(Action action)
    {
        try
        {
            action();
        }
        catch (Pkcs11Exception ex)
        {
            throw new RpcException((ulong)ex.RV, $"{ex.Method}: {ex.RV}");
        }
    }

    private void DropSession(ulong slotId)
    {
        if (_userSessions.Remove(slotId, out var s))
        {
            try { s.Dispose(); } catch (Exception) { }
        }
    }

    private void UnloadAll()
    {
        foreach (var id in _userSessions.Keys.ToList()) DropSession(id);
        foreach (var lib in _libraries)
        {
            try { lib.Library.Dispose(); } // C_Finalize + FreeLibrary: releases vendor handles / file locks
            catch (Exception ex) { Log?.Invoke($"Unloading {lib.Path}: {ex.Message}"); }
        }
        _libraries.Clear();
        _loaded = false;
    }

    public void Dispose() => UnloadAll();
}

internal static class CoreCkr
{
    public const ulong SLOT_ID_INVALID = DscSync.Core.Pkcs11.CKR.SLOT_ID_INVALID;
    public const ulong TOKEN_NOT_PRESENT = DscSync.Core.Pkcs11.CKR.TOKEN_NOT_PRESENT;
    public const ulong USER_NOT_LOGGED_IN = DscSync.Core.Pkcs11.CKR.USER_NOT_LOGGED_IN;
    public const ulong KEY_HANDLE_INVALID = DscSync.Core.Pkcs11.CKR.KEY_HANDLE_INVALID;
}
