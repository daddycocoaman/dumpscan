from itertools import accumulate

import construct
from construct import Hex, Int64ul, Pass, Struct, this


def _track_rva_addr(memranges, ctx):
    """Adds the RVA to each range enumerated"""

    # Starting with the BaseRva, we need to keep track of each DataSize to know where the
    # StartOfMemoryRange maps to the RVA in the minidump
    rva_list = list(
        accumulate([memrange.DataSize for memrange in memranges], initial=ctx.BaseRva)
    )
    for index, memrange in enumerate(memranges):
        memrange.DumpRva = rva_list[index]
        # print(memrange.Rva, memrange.DataSize)


MINIDUMP_MEMORY_DESCRIPTOR64 = Struct(
    "StartOfMemoryRange" / Hex(Int64ul),
    "DataSize" / Hex(Int64ul),
    "DumpRva" / Pass,  # We add Pass here as a placeholder for _track_rva_addr
)

MINIDUMP_MEMORY64_LIST = Struct(
    "NumberOfMemoryRanges" / Int64ul,
    "BaseRva" / Hex(Int64ul),
    "MemoryRanges"
    / (MINIDUMP_MEMORY_DESCRIPTOR64)[this.NumberOfMemoryRanges]
    * _track_rva_addr,
)
