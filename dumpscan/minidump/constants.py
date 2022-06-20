import enum


# Thanks to Skelsec - https://github.com/skelsec/minidump/blob/4945b1011ac202c58003b0198820bc8521eb5af5/minidump/constants.py
class MINIDUMP_STREAM_TYPE(enum.IntEnum):
    """Enum for Minidump stream types"""

    UnusedStream = 0
    ReservedStream0 = 1
    ReservedStream1 = 2
    ThreadListStream = 3
    ModuleListStream = 4
    MemoryListStream = 5
    ExceptionStream = 6
    SystemInfoStream = 7
    ThreadExListStream = 8
    Memory64ListStream = 9
    CommentStreamA = 10
    CommentStreamW = 11
    HandleDataStream = 12
    FunctionTableStream = 13
    UnloadedModuleListStream = 14
    MiscInfoStream = 15
    MemoryInfoListStream = 16
    ThreadInfoListStream = 17
    HandleOperationListStream = 18
    TokenStream = 19
    JavaScriptDataStream = 20
    SystemMemoryInfoStream = 21
    ProcessVmCountersStream = 22
    ThreadNamesStream = 24
    ceStreamNull = 0x8000
    ceStreamSystemInfo = 0x8001
    ceStreamException = 0x8002
    ceStreamModuleList = 0x8003
    ceStreamProcessList = 0x8004
    ceStreamThreadList = 0x8005
    ceStreamThreadContextList = 0x8006
    ceStreamThreadCallStackList = 0x8007
    ceStreamMemoryVirtualList = 0x8008
    ceStreamMemoryPhysicalList = 0x8009
    ceStreamBucketParameters = 0x800A
    ceStreamProcessModuleMap = 0x800B
    ceStreamDiagnosisList = 0x800C
    LastReservedStream = 0xFFFF


# Thanks to Skelsec - https://github.com/skelsec/minidump/blob/4945b1011ac202c58003b0198820bc8521eb5af5/minidump/constants.py
class MINIDUMP_TYPE(enum.IntFlag):
    """Enum for Minidump types"""

    MiniDumpNormal = 0x00000000
    MiniDumpWithDataSegs = 0x00000001
    MiniDumpWithFullMemory = 0x00000002
    MiniDumpWithHandleData = 0x00000004
    MiniDumpFilterMemory = 0x00000008
    MiniDumpScanMemory = 0x00000010
    MiniDumpWithUnloadedModules = 0x00000020
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040
    MiniDumpFilterModulePaths = 0x00000080
    MiniDumpWithProcessThreadData = 0x00000100
    MiniDumpWithPrivateReadWriteMemory = 0x00000200
    MiniDumpWithoutOptionalData = 0x00000400
    MiniDumpWithFullMemoryInfo = 0x00000800
    MiniDumpWithThreadInfo = 0x00001000
    MiniDumpWithCodeSegs = 0x00002000
    MiniDumpWithoutAuxiliaryState = 0x00004000
    MiniDumpWithFullAuxiliaryState = 0x00008000
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000
    MiniDumpIgnoreInaccessibleMemory = 0x00020000
    MiniDumpWithTokenInformation = 0x00040000
    MiniDumpWithModuleHeaders = 0x00080000
    MiniDumpFilterTriage = 0x00100000
    MiniDumpValidTypeFlags = 0x001FFFFF
