from enum import IntEnum
from math import ceil, floor
from construct import (
    Padding,  # We use Padding to fill up the space between the fields that are unknown.
)
from construct import (
    Array,
    Byte,
    Bytes,
    BytesInteger,
    CancelParsing,
    Const,
    Enum,
    ExprSymmetricAdapter,
    Flag,
    Hex,
    Int32ul,
    Int64ul,
    OneOf,
    Struct,
    Union,
    this,
)

################################################################################
### ALIAS ###
################################################################################
Int32ulFlag = ExprSymmetricAdapter(Int32ul, lambda obj, ctx: bool(obj))

################################################################################
### CONDITIONS ###
################################################################################
def divisible_by_1024(obj, ctx):
    if not obj or not obj % 1024 == 0:
        raise CancelParsing


def divisible_by_128(obj, ctx):
    if not obj or not obj % 128 == 0:
        raise CancelParsing


def validate_ecc_size(obj, ctx):
    # Since ECC keys have weird sizes, we need to validate them. For example, 521 bits
    # Can have a private key size of 65-66 bytes and a public key size of 130-131 bytes.
    # So we check if the byte size is between the floor and ceiling of the expected size.
    if not obj:
        raise CancelParsing

    key_type, _, size, _ = str(ctx.Magic).split("_")
    size = int(size.strip("P"))
    byte_size = size // 8

    if not floor(byte_size) <= obj <= ceil(byte_size):
        raise CancelParsing


################################################################################
### ENUMS ###
################################################################################


class ECC_MAGIC(IntEnum):
    ECDH_PUBLIC_P256_MAGIC = 0x314B4345
    ECDH_PRIVATE_P256_MAGIC = 0x324B4345
    ECDH_PUBLIC_P384_MAGIC = 0x334B4345
    ECDH_PRIVATE_P384_MAGIC = 0x344B4345
    ECDH_PUBLIC_P521_MAGIC = 0x354B4345
    ECDH_PRIVATE_P521_MAGIC = 0x364B4345
    ECDSA_PUBLIC_P256_MAGIC = 0x31534345
    ECDSA_PRIVATE_P256_MAGIC = 0x32534345
    ECDSA_PUBLIC_P384_MAGIC = 0x33534345
    ECDSA_PRIVATE_P384_MAGIC = 0x34534345
    ECDSA_PUBLIC_P521_MAGIC = 0x35534345
    ECDSA_PRIVATE_P521_MAGIC = 0x36534345


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
    "fdef" / BytesInteger(this.cbSize - 0x20, swapped=True),
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
    "bIndexGenG" / Byte,
    Padding(3),
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

################################################################################
### BCrypt STRUCTS ###
################################################################################

BCRYPT_RSAKEY = Struct(
    "Magic" / OneOf(Bytes(4), (b"RSA1", b"RSA2", b"RSA3")),
    "BitLength" / Int32ul * divisible_by_1024,
    "cbPublicExp" / Int32ul,
    "cbModulus" / Int32ul,
    "cbPrime1" / Int32ul,
    "cbPrime2" / Int32ul,
)

BCRYPT_RSAPUBLIC = Struct(
    *BCRYPT_RSAKEY.subcons,
    "PublicExponent" / BytesInteger(this.cbPublicExp),
    "Modulus" / BytesInteger(this.cbModulus),
)

BCRYPT_RSAPRIVATE = Struct(
    *BCRYPT_RSAPUBLIC.subcons,
    "Prime1" / BytesInteger(this.cbPrime1),
    "Prime2" / BytesInteger(this.cbPrime2),
)

BCRYPT_RSAFULLPRIVATE = Struct(
    *BCRYPT_RSAPRIVATE.subcons,
    "Exponent1" / BytesInteger(this.cbPrime1),
    "Exponent2" / BytesInteger(this.cbPrime2),
    "Coefficient" / BytesInteger(this.cbPrime1),
    "PrivateExponent" / BytesInteger(this.cbModulus),
)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
BCRYPT_DSAKEY_V1 = Struct(
    "Magic" / OneOf(Bytes(4), (b"DSPB", b"DSPV")),
    "cbKey" / Int32ul,
    "Count" / BytesInteger(4),
    "Seed" / BytesInteger(20),
    "q" / BytesInteger(20),
)

BCRYPT_DSAPUBLIC_V1 = Struct(
    *BCRYPT_DSAKEY_V1.subcons,
    "Modulus" / BytesInteger(this.cbKey),
    "Generator" / BytesInteger(this.cbKey),
    "Public" / BytesInteger(this.cbKey),
)

BCRYPT_DSAPRIVATE_V1 = Struct(
    *BCRYPT_DSAPUBLIC_V1.subcons,
    "PrivateExponent" / BytesInteger(20),
)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
BCRYPT_DSAKEY_V2 = Struct(
    "Magic" / OneOf(Bytes(4), (b"DPB2", b"DPV2")),
    "cbKey" / Int32ul,
    "HashAlgorithm" / Enum(Int32ul, SHA1=0, SHA256=1, SHA512=2),
    "DSAFipsVersion" / Int32ul,
    "cbSeedLength" / Int32ul,
    "cbGroupSize" / Int32ul,  # q is 32 bytes long.
    "Count" / Byte[4],
)

BCRYPT_DSAPUBLIC_V2 = Struct(
    *BCRYPT_DSAKEY_V2.subcons,
    "Seed" / BytesInteger(this.cbSeedLength),
    "q" / BytesInteger(this.cbGroupSize),
    "Modulus" / BytesInteger(this.cbKey),
    "Generator" / BytesInteger(this.cbKey),
    "Public" / BytesInteger(this.cbKey),
)

BCRYPT_DSAPRIVATE_V2 = Struct(
    *BCRYPT_DSAPUBLIC_V2.subcons, "PrivateExponent" / BytesInteger(this.cbGroupSize)
)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob

BCRYPT_ECCKEY = Struct(
    "Magic" / Enum(Int32ul, ECC_MAGIC), "cbKey" / Int32ul * validate_ecc_size
)

BCRYPT_ECCPUBLIC = Struct(
    *BCRYPT_ECCKEY.subcons,
    "X" / BytesInteger(this.cbKey),
    "Y" / BytesInteger(this.cbKey),
)

BCRYPT_ECCPRIVATE = Struct(*BCRYPT_ECCPUBLIC.subcons, "d" / BytesInteger(this.cbKey))

BCRYPT_DHKEY = Struct(
    "Magic" / OneOf(Bytes(4), (b"DHPB", b"DHPV")), "cbKey" / Int32ul * divisible_by_128
)

BCRYPT_DHPUBLIC = Struct(
    *BCRYPT_DHKEY.subcons,
    "Modulus" / BytesInteger(this.cbKey),
    "Generator" / BytesInteger(this.cbKey),
)

BCRYPT_DHPRIVATE = Struct(
    *BCRYPT_DHPUBLIC.subcons, "PrivateExponent" / BytesInteger(this.cbKey)
)
