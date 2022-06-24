import construct
from construct import Int32ul, Pointer, Struct, Switch, this

from ..constants import MINIDUMP_STREAM_TYPE
from .common import MINIDUMP_LOCATION_DESCRIPTOR
from .MinidumpMemory64List import MINIDUMP_MEMORY64_LIST
from .MinidumpMemoryList import MINIDUMP_MEMORY_LIST
from .MinidumpThreadList import MINIDUMP_THREAD_LIST

MINIDUMP_DIRECTORY = Struct(
    "StreamType" / construct.Enum(Int32ul, MINIDUMP_STREAM_TYPE),
    "Location" / MINIDUMP_LOCATION_DESCRIPTOR,
    "Data"
    / Pointer(
        this.Location.Rva,
        Switch(
            lambda this: int(this.StreamType),
            {
                MINIDUMP_STREAM_TYPE.MemoryListStream.value: MINIDUMP_MEMORY_LIST,
                MINIDUMP_STREAM_TYPE.Memory64ListStream.value: MINIDUMP_MEMORY64_LIST,
                MINIDUMP_STREAM_TYPE.ThreadListStream.value: MINIDUMP_THREAD_LIST,
            },
            default=None,
        ),
    ),
)
