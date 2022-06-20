from construct import Hex, Int32ul, Int64ul, Struct

MINIDUMP_LOCATION_DESCRIPTOR = Struct("DataSize" / Int32ul, "Rva" / Hex(Int32ul))
MINIDUMP_LOCATION_DESCRIPTOR_64 = Struct("DataSize" / Int64ul, "Rva" / Hex(Int64ul))
