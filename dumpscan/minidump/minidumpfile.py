import binascii
from pathlib import Path
from struct import unpack
from typing import Dict, Generator, Tuple, TypeVar

import construct
import yara
from construct import Array, CString, RepeatUntil, Seek, Struct, this

from dumpscan.minidump.structs.MinidumpThreadList import (
    MINIDUMP_PEB,
    MINIDUMP_PROCESS_PARAMETERS,
    MINIDUMP_TEB,
)

from ..common.rules import YARA_RULES
from .constants import MINIDUMP_STREAM_TYPE
from .structs import *

T = TypeVar("T")

MINIDUMP_FILE = Struct(
    "Header" / MINIDUMP_HEADER,
    Seek(this.Header.StreamDirectoryRva),
    "Dirs" / construct.Array(this.Header.NumberOfStreams, MINIDUMP_DIRECTORY),
)


class MinidumpFile:
    """Minidump class that parses Windows Minidump format"""

    def __init__(self, filepath: Path):
        self.file = filepath
        self.dump = MINIDUMP_FILE.parse_file(str(filepath.absolute()))
        self._memory_list = self._get_dir(MINIDUMP_STREAM_TYPE.MemoryListStream)
        self._memory64_list = self._get_dir(MINIDUMP_STREAM_TYPE.Memory64ListStream)
        self.thread_list = self._get_dir(MINIDUMP_STREAM_TYPE.ThreadListStream)
        self.memory = self._memory_list or self._memory64_list

    def _get_dir(self, dir_type: T) -> T | None:
        return next(
            (dir for dir in self.dump.Dirs if int(dir.StreamType) == dir_type),
            None,
        )

    def find_section(self, address: int):
        """Finds the section of memory where the address lives"""

        for section in self.memory.Data.MemoryRanges:
            if (
                int(section.StartOfMemoryRange)
                <= address
                <= int(section.StartOfMemoryRange) + int(section.DataSize)
            ):
                return section
        return None

    def read_all_memory64(
        self,
    ) -> Generator[Tuple[Struct, bytes], None, None]:
        """Generator to read all memory64 sections of minidump"""

        with self.file.open("rb") as reader:
            for section in self.memory.Data.MemoryRanges:
                reader.seek(section.DumpRva)
                yield section, reader.read(section.DataSize)

    def read_section(self, section, offset: int, size: int) -> bytes:
        """Reads bytes based on offset from memory section"""

        with self.file.open("rb") as reader:
            reader.seek(section.DumpRva + offset)
            return reader.read(size)

    def read_physical(self, address: int, size: int) -> bytes:
        """Reads bytes based on physical address in dump"""

        if section := self.find_section(address):
            offset = address - section.StartOfMemoryRange
            return self.read_section(section, offset, size)
        else:
            return None

    def get_peb(self):
        """Gets the Process Environment Block (PEB)"""

        thread = self.thread_list.Data.Threads[0]
        teb = MINIDUMP_TEB.parse(self.read_physical(thread.Teb, MINIDUMP_TEB.sizeof()))
        return MINIDUMP_PEB.parse(self.read_physical(teb.PEB, MINIDUMP_PEB.sizeof()))

    def get_process_parameters(self):
        """Gets the process parameter structure in the PEB"""

        peb = self.get_peb()
        return MINIDUMP_PROCESS_PARAMETERS.parse(
            self.read_physical(
                peb.ProcessParameters, MINIDUMP_PROCESS_PARAMETERS.sizeof()
            )
        )

    def get_commandline(self) -> str:
        """Gets the command line strings used to launch the process"""

        params = self.get_process_parameters()
        return self.read_physical(
            params.CommandLine.Buffer, params.CommandLine.Length
        ).decode()


    def get_envars(self) -> Dict[str, str]:
        """Gets the environment variables of the process"""
        params = self.get_process_parameters()

        # Assumption here that the all the envars are in the same section of memory
        section = self.find_section(params.Environment)
        remaining_length = (
            int(section.StartOfMemoryRange) + int(section.DataSize) - params.Environment
        )

        environ_str = self.read_physical(params.Environment, remaining_length)
        envars = RepeatUntil(lambda x, lst, ctx: len(x) == 0, CString("utf16")).parse(environ_str) #fmt: skip
        envar_dict = {}

        # The last value is returned in RepeatUntil and that should be blank so ignore
        for var in envars[:-1]:
            key, value = var.split("=", maxsplit=1)
            envar_dict[key] = value
        return envar_dict