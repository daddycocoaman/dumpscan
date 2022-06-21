from construct import Hex, Int32ul, Int64ul, Padding, Pointer, Seek, Struct, this

from .common import (
    MINIDUMP_LOCATION_DESCRIPTOR,
    MINIDUMP_LOCATION_DESCRIPTOR_64,
    UNICODE_STRING,
)
from .MinidumpMemoryList import MINIDUMP_MEMORY_DESCRIPTOR
from .MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64

MINIDUMP_PEB = Struct("Padding" / Padding(0x20), "ProcessParameters" / Hex(Int64ul))
MINIDUMP_TEB = Struct("Padding" / Padding(0x60), "PEB" / Hex(Int64ul))

MINIDUMP_PROCESS_PARAMETERS = Struct(
    "Padding" / Padding(0x50),
    "DllPath" / UNICODE_STRING,
    "ImagePathName" / UNICODE_STRING,
    "CommandLine" / UNICODE_STRING,
    "Environment" / Hex(Int64ul),
)

MINIDUMP_THREAD = Struct(
    "ThreadId" / Hex(Int32ul),
    "SuspendCount" / Int32ul,
    "PriorityClass" / Int32ul,
    "Priority" / Int32ul,
    "Teb" / Hex(Int64ul),
    "Stack" / MINIDUMP_MEMORY_DESCRIPTOR64,
    "ThreadContext" / MINIDUMP_LOCATION_DESCRIPTOR,
)

MINIDUMP_THREAD_LIST = Struct(
    "NumberOfThreads" / Int32ul, "Threads" / MINIDUMP_THREAD[this.NumberOfThreads]
)
