from construct import IfThenElse, Int32ul, Int64ul, Struct, this

from .common import MINIDUMP_LOCATION_DESCRIPTOR, MINIDUMP_LOCATION_DESCRIPTOR_64

MINIDUMP_MEMORY_DESCRIPTOR = Struct(
    "StartOfMemoryRange" / Int64ul,
    "MemoryLocation"
    / IfThenElse(
        this.StartOfMemoryRange < 0x100000000,
        MINIDUMP_LOCATION_DESCRIPTOR,
        MINIDUMP_LOCATION_DESCRIPTOR_64,
    ),
    "MemoryLocation" / MINIDUMP_LOCATION_DESCRIPTOR,
)

MINIDUMP_MEMORY_LIST = Struct(
    "NumberOfMemoryRanges" / Int32ul,
    # "MemoryRanges"
    # / (MINIDUMP_MEMORY_DESCRIPTOR)[this.NumberOfMemoryRanges]
    # * _track_rva_addr,
)
