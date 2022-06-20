from construct import Const, FlagsEnum, Hex, Int16ul, Int32ul, Struct, Timestamp

from ..constants import MINIDUMP_TYPE

MINIDUMP_HEADER = Struct(
    "Signature" / Const(b"MDMP"),
    "Version" / Int16ul,
    "Implementation" / Int16ul,
    "NumberOfStreams" / Int32ul,
    "StreamDirectoryRva" / Int32ul,
    "Checksum" / Hex(Int32ul),
    "TimeDateStamp" / Timestamp(Int32ul, 1, 1970),
    "Flags" / FlagsEnum(Int32ul, MINIDUMP_TYPE),
)
