from construct import Hex, Int16ul, Int32ul, Int64ul, Padding, Seek, Struct

MINIDUMP_LOCATION_DESCRIPTOR = Struct("DataSize" / Int32ul, "Rva" / Hex(Int32ul))
MINIDUMP_LOCATION_DESCRIPTOR_64 = Struct("DataSize" / Int64ul, "Rva" / Hex(Int64ul))

UNICODE_STRING = Struct(
    "Length" / Int16ul,
    "MaximumLength" / Int16ul,
    Padding(4),
    "Buffer" / Hex(Int64ul),
)
