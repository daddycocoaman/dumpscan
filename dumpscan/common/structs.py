from construct import Array, Const, Hex, Int32sl, Int32ul, Int64ul, Struct, Union, this

BCRYPT_RSAKEY = Struct(
    "Length" / Int32ul,
    "Magic" / Const(b"KRSM"),
    "Algid" / Hex(Int32ul),
    "ModBitLen" / Int32ul,
    "Unknown1" / Int32sl,
    "Unknown2" / Int32sl,
    "pAlg" / Hex(Int64ul),
    "pKey" / Hex(Int64ul),
)

SYMCRYPT_RSAKEY = Struct(
    "cbTotalSize" / Int32ul,
    "hasPrivateKey" / Int32ul,
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

SYMCRYPT_MODULUS_MONTGOMERY = Struct("inv64" / Hex(Int64ul), "rsqr" / Hex(Int32ul))
SYMCRYPT_MODULUS_PSUEDOMERSENNE = Struct("k" / Int32ul)

SYMCRYPT_INT = Struct(
    "type" / Int32ul,
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "magic" / Int64ul,
    "unknown1" / Int64ul,
    "unknown2" / Int32ul,
    "fdef" / Array((this.cbSize - 0x20) // 4, Int32ul),
)

SYMCRYPT_DIVISOR = Struct(
    "type" / Int32ul,
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "nBits" / Int32ul,
    "magic" / Int64ul,
    "td" / Int64ul,
    "int" / SYMCRYPT_INT,
)

SYMCRYPT_MODULUS = Struct(
    "type" / Int32ul,
    "nDigits" / Int32ul,
    "cbSize" / Int32ul,
    "flags" / Int32ul,
    "cbModElement" / Int32ul,
    "magic" / Int64ul,
    "tm"
    / Union(
        0,
        "montgomery" / SYMCRYPT_MODULUS_MONTGOMERY,
        "pseudoMersenne" / SYMCRYPT_MODULUS_PSUEDOMERSENNE,
    ),
    "pUnknown" / Hex(Int64ul),
    "pUnknown2" / Hex(Int64ul),
    "pUnknown3" / Hex(Int64ul),
    "divisor" / SYMCRYPT_DIVISOR,
)
