namespace DscSync.Core.Pkcs11;

/// <summary>PKCS#11 v2.40 return values (subset used by DSC-Sync).</summary>
public static class CKR
{
    public const ulong OK = 0x000;
    public const ulong CANCEL = 0x001;
    public const ulong HOST_MEMORY = 0x002;
    public const ulong SLOT_ID_INVALID = 0x003;
    public const ulong GENERAL_ERROR = 0x005;
    public const ulong FUNCTION_FAILED = 0x006;
    public const ulong ARGUMENTS_BAD = 0x007;
    public const ulong NO_EVENT = 0x008;
    public const ulong ATTRIBUTE_SENSITIVE = 0x011;
    public const ulong ATTRIBUTE_TYPE_INVALID = 0x012;
    public const ulong DATA_LEN_RANGE = 0x021;
    public const ulong DEVICE_ERROR = 0x030;
    public const ulong DEVICE_MEMORY = 0x031;
    public const ulong DEVICE_REMOVED = 0x032;
    public const ulong FUNCTION_CANCELED = 0x050;
    public const ulong FUNCTION_NOT_SUPPORTED = 0x054;
    public const ulong KEY_HANDLE_INVALID = 0x060;
    public const ulong KEY_TYPE_INCONSISTENT = 0x063;
    public const ulong KEY_FUNCTION_NOT_PERMITTED = 0x068;
    public const ulong MECHANISM_INVALID = 0x070;
    public const ulong MECHANISM_PARAM_INVALID = 0x071;
    public const ulong OBJECT_HANDLE_INVALID = 0x082;
    public const ulong OPERATION_ACTIVE = 0x090;
    public const ulong OPERATION_NOT_INITIALIZED = 0x091;
    public const ulong PIN_INCORRECT = 0x0A0;
    public const ulong PIN_INVALID = 0x0A1;
    public const ulong PIN_LEN_RANGE = 0x0A2;
    public const ulong PIN_EXPIRED = 0x0A3;
    public const ulong PIN_LOCKED = 0x0A4;
    public const ulong SESSION_CLOSED = 0x0B0;
    public const ulong SESSION_HANDLE_INVALID = 0x0B3;
    public const ulong SESSION_PARALLEL_NOT_SUPPORTED = 0x0B4;
    public const ulong SESSION_READ_ONLY = 0x0B5;
    public const ulong TEMPLATE_INCONSISTENT = 0x0D1;
    public const ulong TOKEN_NOT_PRESENT = 0x0E0;
    public const ulong TOKEN_NOT_RECOGNIZED = 0x0E1;
    public const ulong TOKEN_WRITE_PROTECTED = 0x0E2;
    public const ulong USER_ALREADY_LOGGED_IN = 0x100;
    public const ulong USER_NOT_LOGGED_IN = 0x101;
    public const ulong USER_TYPE_INVALID = 0x103;
    public const ulong BUFFER_TOO_SMALL = 0x150;
    public const ulong CRYPTOKI_NOT_INITIALIZED = 0x190;
    public const ulong CRYPTOKI_ALREADY_INITIALIZED = 0x191;
}

public static class CKM
{
    public const ulong RSA_PKCS = 0x0001;
    public const ulong SHA1_RSA_PKCS = 0x0006;
    public const ulong RSA_PKCS_PSS = 0x000D;
    public const ulong SHA1_RSA_PKCS_PSS = 0x000E;
    public const ulong SHA256_RSA_PKCS = 0x0040;
    public const ulong SHA384_RSA_PKCS = 0x0041;
    public const ulong SHA512_RSA_PKCS = 0x0042;
    public const ulong SHA256_RSA_PKCS_PSS = 0x0043;
    public const ulong SHA384_RSA_PKCS_PSS = 0x0044;
    public const ulong SHA512_RSA_PKCS_PSS = 0x0045;
    public const ulong SHA_1 = 0x0220;
    public const ulong SHA256 = 0x0250;
    public const ulong SHA384 = 0x0260;
    public const ulong SHA512 = 0x0270;

    public static readonly ulong[] Supported =
    {
        RSA_PKCS, SHA1_RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, SHA512_RSA_PKCS,
        RSA_PKCS_PSS, SHA1_RSA_PKCS_PSS, SHA256_RSA_PKCS_PSS, SHA384_RSA_PKCS_PSS, SHA512_RSA_PKCS_PSS,
    };

    public static bool IsPss(ulong m) => m is RSA_PKCS_PSS or SHA1_RSA_PKCS_PSS or SHA256_RSA_PKCS_PSS or SHA384_RSA_PKCS_PSS or SHA512_RSA_PKCS_PSS;

    /// <summary>True when the mechanism hashes internally (supports multi-part C_SignUpdate).</summary>
    public static bool IsHashing(ulong m) => m is SHA1_RSA_PKCS or SHA256_RSA_PKCS or SHA384_RSA_PKCS or SHA512_RSA_PKCS
        or SHA1_RSA_PKCS_PSS or SHA256_RSA_PKCS_PSS or SHA384_RSA_PKCS_PSS or SHA512_RSA_PKCS_PSS;

    public static string Name(ulong m) => m switch
    {
        RSA_PKCS => "CKM_RSA_PKCS",
        SHA1_RSA_PKCS => "CKM_SHA1_RSA_PKCS",
        SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        SHA384_RSA_PKCS => "CKM_SHA384_RSA_PKCS",
        SHA512_RSA_PKCS => "CKM_SHA512_RSA_PKCS",
        RSA_PKCS_PSS => "CKM_RSA_PKCS_PSS",
        SHA1_RSA_PKCS_PSS => "CKM_SHA1_RSA_PKCS_PSS",
        SHA256_RSA_PKCS_PSS => "CKM_SHA256_RSA_PKCS_PSS",
        SHA384_RSA_PKCS_PSS => "CKM_SHA384_RSA_PKCS_PSS",
        SHA512_RSA_PKCS_PSS => "CKM_SHA512_RSA_PKCS_PSS",
        _ => $"0x{m:X}",
    };
}

public static class CKG
{
    public const ulong MGF1_SHA1 = 1;
    public const ulong MGF1_SHA256 = 2;
    public const ulong MGF1_SHA384 = 3;
    public const ulong MGF1_SHA512 = 4;
}

public static class CKA
{
    public const ulong CLASS = 0x000;
    public const ulong TOKEN = 0x001;
    public const ulong PRIVATE = 0x002;
    public const ulong LABEL = 0x003;
    public const ulong APPLICATION = 0x010;
    public const ulong VALUE = 0x011;
    public const ulong CERTIFICATE_TYPE = 0x080;
    public const ulong ISSUER = 0x081;
    public const ulong SERIAL_NUMBER = 0x082;
    public const ulong TRUSTED = 0x086;
    public const ulong CERTIFICATE_CATEGORY = 0x087;
    public const ulong KEY_TYPE = 0x100;
    public const ulong SUBJECT = 0x101;
    public const ulong ID = 0x102;
    public const ulong SENSITIVE = 0x103;
    public const ulong ENCRYPT = 0x104;
    public const ulong DECRYPT = 0x105;
    public const ulong WRAP = 0x106;
    public const ulong UNWRAP = 0x107;
    public const ulong SIGN = 0x108;
    public const ulong SIGN_RECOVER = 0x109;
    public const ulong VERIFY = 0x10A;
    public const ulong VERIFY_RECOVER = 0x10B;
    public const ulong DERIVE = 0x10C;
    public const ulong START_DATE = 0x110;
    public const ulong END_DATE = 0x111;
    public const ulong MODULUS = 0x120;
    public const ulong MODULUS_BITS = 0x121;
    public const ulong PUBLIC_EXPONENT = 0x122;
    public const ulong EXTRACTABLE = 0x162;
    public const ulong LOCAL = 0x163;
    public const ulong NEVER_EXTRACTABLE = 0x164;
    public const ulong ALWAYS_SENSITIVE = 0x165;
    public const ulong MODIFIABLE = 0x170;
    public const ulong ALWAYS_AUTHENTICATE = 0x202;
}

public static class CKO
{
    public const ulong DATA = 0;
    public const ulong CERTIFICATE = 1;
    public const ulong PUBLIC_KEY = 2;
    public const ulong PRIVATE_KEY = 3;
}

public static class CKF
{
    // slot flags
    public const ulong TOKEN_PRESENT = 0x1;
    public const ulong REMOVABLE_DEVICE = 0x2;
    public const ulong HW_SLOT = 0x4;
    // token flags
    public const ulong WRITE_PROTECTED = 0x2;
    public const ulong LOGIN_REQUIRED = 0x4;
    public const ulong USER_PIN_INITIALIZED = 0x8;
    public const ulong TOKEN_INITIALIZED = 0x400;
    // session flags
    public const ulong RW_SESSION = 0x2;
    public const ulong SERIAL_SESSION = 0x4;
    // mechanism flags
    public const ulong HW = 0x1;
    public const ulong SIGN = 0x800;
    public const ulong VERIFY = 0x2000;
    // C_WaitForSlotEvent
    public const ulong DONT_BLOCK = 0x1;
}

public static class CKU
{
    public const ulong SO = 0;
    public const ulong USER = 1;
    public const ulong CONTEXT_SPECIFIC = 2;
}

public static class CKS
{
    public const ulong RO_PUBLIC_SESSION = 0;
    public const ulong RO_USER_FUNCTIONS = 1;
    public const ulong RW_PUBLIC_SESSION = 2;
    public const ulong RW_USER_FUNCTIONS = 3;
}

public static class CKK
{
    public const ulong RSA = 0;
}

public static class CKC
{
    public const ulong X_509 = 0;
}
