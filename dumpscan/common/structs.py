from construct import (
    Array,
    ExprSymmetricAdapter,
    Flag,
    Const,
    Hex,
    Int32ul,
    Int64ul,
    Struct,
    Union,
    this,
    Padding,  # We use Padding to fill up the space between the fields that are unknown.
)

################################################################################
### ALIAS ###
################################################################################
Int32ulFlag = ExprSymmetricAdapter(Int32ul, lambda obj, ctx: bool(obj))

################################################################################
### COMMON STRUCTS ###
################################################################################
SYMCRYPT_MODULUS_MONTGOMERY = Struct("inv64" / Int64ul, "rsqr" / Int32ul)
SYMCRYPT_MODULUS_PSUEDOMERSENNE = Struct("k" / Int32ul)

SYMCRYPT_INT = Struct(
    "type" / Hex(Int32ul),
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "magic" / Hex(Int64ul),
    Padding(12),
    "fdef" / Array((this.cbSize - 0x20) // 4, Hex(Int32ul)),
)

SYMCRYPT_DIVISOR = Struct(
    "type" / Hex(Int32ul),
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "nBits" / Int32ul,
    "magic" / Hex(Int64ul),
    "td" / Int64ul,
    "int" / SYMCRYPT_INT,
)

SYMCRYPT_MODULUS = Struct(
    "type" / Hex(Int32ul),
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "flags" / Int32ul,
    "cbModElement" / Int32ul,
    "magic" / Hex(Int64ul),
    "tm"
    / Union(
        0,
        "montgomery" / SYMCRYPT_MODULUS_MONTGOMERY,
        "pseudoMersenne" / SYMCRYPT_MODULUS_PSUEDOMERSENNE,
    ),
    Padding(24),
    "divisor" / SYMCRYPT_DIVISOR,
)

################################################################################
### MSCRYPT STRUCTS ###
################################################################################

MSCRYPT_RSAKEY = Struct(
    "Length" / Int32ul,
    "Magic" / Const(b"KRSM"),
    "Algid" / Hex(Int32ul),
    "ModBitLen" / Int32ul,
    Padding(8),
    "pAlg" / Hex(Int64ul),
    "pKey" / Hex(Int64ul),
)

MSCRYPT_DSAKEY = Struct(
    "Length" / Int32ul,
    "Magic" / Const(b"YKSM"),
    "Algid" / Hex(Int32ul),
    "KeyLength" / Int32ul,
    Padding(16),
    "pDlGroup" / Hex(Int64ul),  # Assumption. Always the same as SYMCRYPT_DLKEY.pDlGroup
    "pKey" / Hex(Int64ul),
)

################################################################################
### SymCrypt STRUCTS ###
################################################################################

SYMCRYPT_RSAKEY = Struct(
    "cbTotalSize" / Int32ul,
    "hasPrivateKey" / Int32ulFlag,
    "nSetBitsOfModulus" / Int32ul,
    "nBitsOfModulus" / Int32ul,
    "nDigitsOfModulus" / Int32ul,
    "nPubExp" / Int32ul,
    "nPrimes" / Int32ul,
    "nBitsOfPrimes" / Array(2, Int32ul),
    "nDigitsOfPrimes" / Array(2, Int32ul),
    "nMaxDigitsOfPrimes" / Array(1, Int32ul),
    "au64PubExp" / Hex(Int64ul),
    "pbPrimes" / Array(2, Hex(Int64ul)),
    "pbCrtInverses" / Array(2, Hex(Int64ul)),
    "pbPrivExps" / Array(1, Hex(Int64ul)),
    "pbCrtPrivExps" / Array(2, Hex(Int64ul)),
    "pmModulus" / Hex(Int64ul),
    "pmPrimes" / Array(2, Hex(Int64ul)),
    "peCrtInverses" / Array(2, Hex(Int64ul)),
    "piPrivExps" / Array(1, Hex(Int64ul)),
    "piCrtPrivExps" / Array(2, Hex(Int64ul)),
    "magic" / Hex(Int64ul),
)

# https://github.com/microsoft/SymCrypt/blob/833b992f40dab7850b09b543bc8e85be5b9d5060/inc/symcrypt_internal.h#L2082
SYMCRYPT_DLGROUP = Struct(
    "cbTotalSize" / Int32ul,
    "fHasPrimeQ" / Int32ulFlag,
    "nBitsOfP" / Int32ul,
    "cbPrimeP" / Int32ul,
    "nDigitsOfP" / Int32ul,
    "nMaxBitsOfP" / Int32ul,
    "nBitsOfQ" / Int32ul,
    "cbPrimeQ" / Int32ul,
    "nDigitsOfQ" / Int32ul,
    "nMaxBitsOfQ" / Int32ul,
    "isSafePrimeGroup" / Int32ul,
    "nMinBitsPriv" / Int32ul,
    "nDefaultBitsPriv" / Int32ul,
    "nBitsOfSeed" / Int32ul,
    "cbSeed" / Int32ul,
    "eFipsStandard" / Hex(Int32ul),
    "pHashAlgorithm" / Hex(Int64ul),
    "dwGenCounter" / Int32ul,
    "bIndexGenG" / Int32ul,
    "pbQ" / Hex(Int64ul),
    "pmP" / Hex(Int64ul),
    "pmQ" / Hex(Int64ul),
    "peG" / Hex(Int64ul),
    "pbSeed" / Hex(Int64ul),
)

# https://github.com/microsoft/SymCrypt/blob/833b992f40dab7850b09b543bc8e85be5b9d5060/inc/symcrypt_internal.h#L2136
SYMCRYPT_DLKEY = Struct(
    "pDlgroup" / Hex(Int64ul),
    "fHasPrivateKey" / Flag,
    "fPrivateModQ" / Flag,
    "nBitsPriv" / Int32ul,
    Padding(2),  # There's an alignment issue here so we pad two bytes
    "pbPrivate" / Hex(Int64ul),
    "pePublicKey" / Hex(Int64ul),
    "piPrivateKey" / Hex(Int64ul),
)
