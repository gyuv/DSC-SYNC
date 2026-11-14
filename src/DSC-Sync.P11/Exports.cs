using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;

namespace DscSync.P11;

/// <summary>
/// Cryptoki (PKCS#11 v2.40) exports of DSC-Sync-P11.dll. Windows ABI: CK_ULONG is 32-bit on both x86 and x64,
/// structures are packed to 1 byte and functions use cdecl. All state lives in <see cref="VirtualP11Core"/>.
/// </summary>
public static unsafe class Exports
{
    private const int UlongSize = 4;
    private const uint UnavailableInformation = 0xFFFFFFFF;
    private const int FunctionCount = 68;
    private static readonly VirtualP11Core Core = new(() => new PipeP11Channel(), UlongSize);
    private static byte* _functionList;
    private static readonly object InitLock = new();

    // ------------------------------------------------------------------ helpers

    private static uint R(ulong rv) => (uint)rv;

    private static uint Guard(Func<ulong> body)
    {
        try { return R(body()); }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    private static void Pad(byte* dst, int len, string value)
    {
        new Span<byte>(dst, len).Fill((byte)' ');
        var bytes = Encoding.UTF8.GetBytes(value);
        int n = Math.Min(len, bytes.Length);
        // avoid cutting a multi-byte UTF-8 sequence
        while (n > 0 && n < bytes.Length && (bytes[n] & 0xC0) == 0x80) n--;
        bytes.AsSpan(0, n).CopyTo(new Span<byte>(dst, len));
    }

    private static void U32(byte* p, int offset, ulong value) => Unsafe.WriteUnaligned(p + offset, (uint)value);
    private static uint RU32(byte* p, int offset) => Unsafe.ReadUnaligned<uint>(p + offset);
    private static IntPtr RPtr(byte* p, int offset) => Unsafe.ReadUnaligned<IntPtr>(p + offset);
    private static void WPtr(byte* p, int offset, IntPtr v) => Unsafe.WriteUnaligned(p + offset, v);

    private static uint CopyList(ulong[] items, uint* pList, uint* pulCount)
    {
        if (pulCount == null) return R(CKR.ARGUMENTS_BAD);
        if (pList == null)
        {
            *pulCount = (uint)items.Length;
            return R(CKR.OK);
        }
        if (*pulCount < items.Length)
        {
            *pulCount = (uint)items.Length;
            return R(CKR.BUFFER_TOO_SMALL);
        }
        for (int i = 0; i < items.Length; i++) pList[i] = (uint)items[i];
        *pulCount = (uint)items.Length;
        return R(CKR.OK);
    }

    private static uint ReturnBytes(byte[] value, byte* pOut, uint* pulLen)
    {
        if (pulLen == null) return R(CKR.ARGUMENTS_BAD);
        if (pOut == null)
        {
            *pulLen = (uint)value.Length;
            return R(CKR.OK);
        }
        if (*pulLen < value.Length)
        {
            *pulLen = (uint)value.Length;
            return R(CKR.BUFFER_TOO_SMALL);
        }
        value.CopyTo(new Span<byte>(pOut, value.Length));
        *pulLen = (uint)value.Length;
        return R(CKR.OK);
    }

    // ------------------------------------------------------------------ function list

    [UnmanagedCallersOnly(EntryPoint = "C_GetFunctionList", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetFunctionList(IntPtr* ppFunctionList)
    {
        if (ppFunctionList == null) return R(CKR.ARGUMENTS_BAD);
        lock (InitLock)
        {
            if (_functionList == null) _functionList = BuildFunctionList();
        }
        *ppFunctionList = (IntPtr)_functionList;
        return R(CKR.OK);
    }

    private static byte* BuildFunctionList()
    {
        int size = 2 + FunctionCount * IntPtr.Size;
        var p = (byte*)NativeMemory.AllocZeroed((nuint)size);
        p[0] = 2; p[1] = 40;
        IntPtr ns = (IntPtr)(delegate* unmanaged[Cdecl]<uint>)&NotSupported;
        var f = new IntPtr[FunctionCount];
        for (int i = 0; i < f.Length; i++) f[i] = ns;
        f[0] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, uint>)&C_Initialize;
        f[1] = (IntPtr)(delegate* unmanaged[Cdecl]<void*, uint>)&C_Finalize;
        f[2] = (IntPtr)(delegate* unmanaged[Cdecl]<byte*, uint>)&C_GetInfo;
        f[3] = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr*, uint>)&C_GetFunctionList;
        f[4] = (IntPtr)(delegate* unmanaged[Cdecl]<byte, uint*, uint*, uint>)&C_GetSlotList;
        f[5] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint>)&C_GetSlotInfo;
        f[6] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint>)&C_GetTokenInfo;
        f[7] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint*, uint*, uint>)&C_GetMechanismList;
        f[8] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, byte*, uint>)&C_GetMechanismInfo;
        // 9 C_InitToken, 10 C_InitPIN, 11 C_SetPIN: not supported (token administration stays on the Local PC)
        f[12] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, void*, void*, uint*, uint>)&C_OpenSession;
        f[13] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_CloseSession;
        f[14] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_CloseAllSessions;
        f[15] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint>)&C_GetSessionInfo;
        // 16 C_GetOperationState, 17 C_SetOperationState
        f[18] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, byte*, uint, uint>)&C_Login;
        f[19] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_Logout;
        // 20 C_CreateObject, 21 C_CopyObject, 22 C_DestroyObject
        f[23] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, uint*, uint>)&C_GetObjectSize;
        f[24] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, byte*, uint, uint>)&C_GetAttributeValue;
        // 25 C_SetAttributeValue
        f[26] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint, uint>)&C_FindObjectsInit;
        f[27] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint*, uint, uint*, uint>)&C_FindObjects;
        f[28] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_FindObjectsFinal;
        // 29..41 Encrypt / Decrypt / Digest families: not supported (signing-only token proxy)
        f[42] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint, uint>)&C_SignInit;
        f[43] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint*, uint>)&C_Sign;
        f[44] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint, uint>)&C_SignUpdate;
        f[45] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint*, uint>)&C_SignFinal;
        // 46..63 SignRecover, Verify*, dual-function, key management: not supported
        f[64] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, byte*, uint, uint>)&C_GenerateRandom;
        f[65] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_GetFunctionStatus;
        f[66] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint>)&C_CancelFunction;
        f[67] = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint*, void*, uint>)&C_WaitForSlotEvent;
        for (int i = 0; i < f.Length; i++) WPtr(p, 2 + i * IntPtr.Size, f[i]);
        return p;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint NotSupported() => R(CKR.FUNCTION_NOT_SUPPORTED);

    // ------------------------------------------------------------------ general

    [UnmanagedCallersOnly(EntryPoint = "C_Initialize", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_Initialize(void* pInitArgs) => Guard(() => Core.Initialize());

    [UnmanagedCallersOnly(EntryPoint = "C_Finalize", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_Finalize(void* pReserved) => pReserved != null ? R(CKR.ARGUMENTS_BAD) : Guard(() => Core.Finalize());

    [UnmanagedCallersOnly(EntryPoint = "C_GetInfo", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetInfo(byte* pInfo)
    {
        if (pInfo == null) return R(CKR.ARGUMENTS_BAD);
        if (!Core.IsInitialized) return R(CKR.CRYPTOKI_NOT_INITIALIZED);
        pInfo[0] = 2; pInfo[1] = 40;
        Pad(pInfo + 2, 32, VirtualP11Core.ManufacturerId);
        U32(pInfo, 34, 0);
        Pad(pInfo + 38, 32, VirtualP11Core.LibraryDescription);
        pInfo[70] = 1; pInfo[71] = 0;
        return R(CKR.OK);
    }

    // ------------------------------------------------------------------ slots & tokens

    [UnmanagedCallersOnly(EntryPoint = "C_GetSlotList", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetSlotList(byte tokenPresent, uint* pSlotList, uint* pulCount)
    {
        try
        {
            var rv = Core.GetSlotList(tokenPresent != 0, out var slots);
            return rv != CKR.OK ? R(rv) : CopyList(slots, pSlotList, pulCount);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetSlotInfo", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetSlotInfo(uint slotId, byte* pInfo)
    {
        if (pInfo == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.GetSlotInfo(slotId, out var info);
            if (rv != CKR.OK) return R(rv);
            Pad(pInfo, 64, info.Description);
            Pad(pInfo + 64, 32, info.Manufacturer);
            U32(pInfo, 96, info.Flags);
            pInfo[100] = 1; pInfo[101] = 0; pInfo[102] = 1; pInfo[103] = 0;
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetTokenInfo", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetTokenInfo(uint slotId, byte* pInfo)
    {
        if (pInfo == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.GetTokenInfo(slotId, out var t);
            if (rv != CKR.OK) return R(rv);
            Pad(pInfo, 32, t.Label);
            Pad(pInfo + 32, 32, t.Manufacturer);
            Pad(pInfo + 64, 16, t.Model);
            Pad(pInfo + 80, 16, t.Serial);
            U32(pInfo, 96, t.Flags);
            U32(pInfo, 100, 0);                       // ulMaxSessionCount: CK_EFFECTIVELY_INFINITE
            U32(pInfo, 104, t.SessionCount);
            U32(pInfo, 108, 0);                       // ulMaxRwSessionCount
            U32(pInfo, 112, t.RwSessionCount);
            U32(pInfo, 116, t.MaxPin);
            U32(pInfo, 120, t.MinPin);
            U32(pInfo, 124, UnavailableInformation);
            U32(pInfo, 128, UnavailableInformation);
            U32(pInfo, 132, UnavailableInformation);
            U32(pInfo, 136, UnavailableInformation);
            pInfo[140] = 1; pInfo[141] = 0; pInfo[142] = 1; pInfo[143] = 0;
            Pad(pInfo + 144, 16, "");
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetMechanismList", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetMechanismList(uint slotId, uint* pList, uint* pulCount)
    {
        try
        {
            var rv = Core.GetMechanismList(slotId, out var list);
            return rv != CKR.OK ? R(rv) : CopyList(list, pList, pulCount);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetMechanismInfo", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetMechanismInfo(uint slotId, uint type, byte* pInfo)
    {
        if (pInfo == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.GetMechanismInfo(slotId, type, out var min, out var max, out var flags);
            if (rv != CKR.OK) return R(rv);
            U32(pInfo, 0, min);
            U32(pInfo, 4, max);
            U32(pInfo, 8, flags);
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_WaitForSlotEvent", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_WaitForSlotEvent(uint flags, uint* pSlot, void* pReserved)
    {
        if (pSlot == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.WaitForSlotEvent((flags & CKF.DONT_BLOCK) != 0, out var slot);
            if (rv == CKR.OK) *pSlot = (uint)slot;
            return R(rv);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    // ------------------------------------------------------------------ sessions

    [UnmanagedCallersOnly(EntryPoint = "C_OpenSession", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_OpenSession(uint slotId, uint flags, void* pApplication, void* notify, uint* phSession)
    {
        if (phSession == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.OpenSession(slotId, flags, out var h);
            if (rv == CKR.OK) *phSession = (uint)h;
            return R(rv);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_CloseSession", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_CloseSession(uint hSession) => Guard(() => Core.CloseSession(hSession));

    [UnmanagedCallersOnly(EntryPoint = "C_CloseAllSessions", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_CloseAllSessions(uint slotId) => Guard(() => Core.CloseAllSessions(slotId));

    [UnmanagedCallersOnly(EntryPoint = "C_GetSessionInfo", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetSessionInfo(uint hSession, byte* pInfo)
    {
        if (pInfo == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.GetSessionInfo(hSession, out var info);
            if (rv != CKR.OK) return R(rv);
            U32(pInfo, 0, info.SlotId);
            U32(pInfo, 4, info.State);
            U32(pInfo, 8, info.Flags);
            U32(pInfo, 12, 0);
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Login", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_Login(uint hSession, uint userType, byte* pPin, uint ulPinLen)
    {
        if (pPin == null) return R(CKR.ARGUMENTS_BAD); // no protected authentication path through the bridge
        try
        {
            var pin = Encoding.UTF8.GetString(pPin, (int)ulPinLen);
            return R(Core.Login(hSession, userType, pin));
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Logout", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_Logout(uint hSession) => Guard(() => Core.Logout(hSession));

    // ------------------------------------------------------------------ objects

    [UnmanagedCallersOnly(EntryPoint = "C_GetObjectSize", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetObjectSize(uint hSession, uint hObject, uint* pulSize)
    {
        if (pulSize == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.ValidateObject(hSession, hObject);
            if (rv != CKR.OK) return R(rv);
            *pulSize = UnavailableInformation;
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetAttributeValue", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetAttributeValue(uint hSession, uint hObject, byte* pTemplate, uint ulCount)
    {
        if (pTemplate == null && ulCount > 0) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.ValidateObject(hSession, hObject);
            if (rv != CKR.OK) return R(rv);
            int stride = UlongSize + IntPtr.Size + UlongSize;
            ulong result = CKR.OK;
            for (int i = 0; i < ulCount; i++)
            {
                byte* a = pTemplate + i * stride;
                uint type = RU32(a, 0);
                byte* pValue = (byte*)RPtr(a, UlongSize);
                uint len = RU32(a, UlongSize + IntPtr.Size);
                var arv = Core.GetAttributeValue(hSession, hObject, type, out var value);
                if (arv != CKR.OK)
                {
                    U32(a, UlongSize + IntPtr.Size, UnavailableInformation);
                    if (result == CKR.OK || result == CKR.BUFFER_TOO_SMALL) result = arv;
                    continue;
                }
                if (pValue == null)
                {
                    U32(a, UlongSize + IntPtr.Size, (uint)value!.Length);
                }
                else if (len < value!.Length)
                {
                    U32(a, UlongSize + IntPtr.Size, UnavailableInformation);
                    if (result == CKR.OK) result = CKR.BUFFER_TOO_SMALL;
                }
                else
                {
                    value.CopyTo(new Span<byte>(pValue, value.Length));
                    U32(a, UlongSize + IntPtr.Size, (uint)value.Length);
                }
            }
            return R(result);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjectsInit", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_FindObjectsInit(uint hSession, byte* pTemplate, uint ulCount)
    {
        if (pTemplate == null && ulCount > 0) return R(CKR.ARGUMENTS_BAD);
        try
        {
            int stride = UlongSize + IntPtr.Size + UlongSize;
            var template = new List<P11Attribute>((int)ulCount);
            for (int i = 0; i < ulCount; i++)
            {
                byte* a = pTemplate + i * stride;
                uint type = RU32(a, 0);
                byte* pValue = (byte*)RPtr(a, UlongSize);
                uint len = RU32(a, UlongSize + IntPtr.Size);
                var bytes = pValue == null ? Array.Empty<byte>() : new ReadOnlySpan<byte>(pValue, (int)len).ToArray();
                template.Add(new P11Attribute(type, bytes));
            }
            return R(Core.FindObjectsInit(hSession, template));
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjects", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_FindObjects(uint hSession, uint* phObject, uint ulMaxObjectCount, uint* pulObjectCount)
    {
        if (phObject == null || pulObjectCount == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.FindObjects(hSession, (int)ulMaxObjectCount, out var objs);
            if (rv != CKR.OK) return R(rv);
            for (int i = 0; i < objs.Length; i++) phObject[i] = (uint)objs[i];
            *pulObjectCount = (uint)objs.Length;
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_FindObjectsFinal", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_FindObjectsFinal(uint hSession) => Guard(() => Core.FindObjectsFinal(hSession));

    // ------------------------------------------------------------------ signing

    [UnmanagedCallersOnly(EntryPoint = "C_SignInit", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_SignInit(uint hSession, byte* pMechanism, uint hKey)
    {
        if (pMechanism == null) return R(CKR.ARGUMENTS_BAD);
        try
        {
            uint mech = RU32(pMechanism, 0);
            byte* pParam = (byte*)RPtr(pMechanism, UlongSize);
            uint paramLen = RU32(pMechanism, UlongSize + IntPtr.Size);
            PssParamsDto? pss = null;
            if (CKM.IsPss(mech))
            {
                if (pParam == null || paramLen < 3 * UlongSize) return R(CKR.MECHANISM_PARAM_INVALID);
                pss = new PssParamsDto { HashAlg = RU32(pParam, 0), Mgf = RU32(pParam, 4), SaltLength = RU32(pParam, 8) };
            }
            return R(Core.SignInit(hSession, mech, pss, hKey));
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_Sign", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_Sign(uint hSession, byte* pData, uint ulDataLen, byte* pSignature, uint* pulSignatureLen)
    {
        if (pulSignatureLen == null || (pData == null && ulDataLen > 0)) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var data = pData == null ? Array.Empty<byte>() : new ReadOnlySpan<byte>(pData, (int)ulDataLen).ToArray();
            return FinishSign(hSession, data, pSignature, pulSignatureLen);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_SignUpdate", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_SignUpdate(uint hSession, byte* pPart, uint ulPartLen)
    {
        if (pPart == null && ulPartLen > 0) return R(CKR.ARGUMENTS_BAD);
        try { return R(Core.SignUpdate(hSession, new ReadOnlySpan<byte>(pPart, (int)ulPartLen))); }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_SignFinal", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_SignFinal(uint hSession, byte* pSignature, uint* pulSignatureLen)
    {
        if (pulSignatureLen == null) return R(CKR.ARGUMENTS_BAD);
        try { return FinishSign(hSession, null, pSignature, pulSignatureLen); }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    private static uint FinishSign(uint hSession, byte[]? data, byte* pSignature, uint* pulSignatureLen)
    {
        var rv = Core.SignatureLength(hSession, out var length);
        if (rv != CKR.OK) return R(rv);
        if (pSignature == null)
        {
            *pulSignatureLen = (uint)length; // size query: operation stays active
            return R(CKR.OK);
        }
        if (*pulSignatureLen < length)
        {
            *pulSignatureLen = (uint)length;
            return R(CKR.BUFFER_TOO_SMALL);
        }
        rv = Core.Sign(hSession, data, out var signature);
        if (rv != CKR.OK) return R(rv);
        return ReturnBytes(signature, pSignature, pulSignatureLen);
    }

    // ------------------------------------------------------------------ misc

    [UnmanagedCallersOnly(EntryPoint = "C_GenerateRandom", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GenerateRandom(uint hSession, byte* pRandom, uint ulLen)
    {
        if (pRandom == null && ulLen > 0) return R(CKR.ARGUMENTS_BAD);
        try
        {
            var rv = Core.GetSessionInfo(hSession, out _);
            if (rv != CKR.OK) return R(rv);
            System.Security.Cryptography.RandomNumberGenerator.Fill(new Span<byte>(pRandom, (int)ulLen));
            return R(CKR.OK);
        }
        catch (Exception) { return R(CKR.GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(EntryPoint = "C_GetFunctionStatus", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_GetFunctionStatus(uint hSession) => R(0x51); // CKR_FUNCTION_NOT_PARALLEL

    [UnmanagedCallersOnly(EntryPoint = "C_CancelFunction", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint C_CancelFunction(uint hSession) => R(0x51);
}
