from pathlib import Path
from struct import unpack
from typing import Dict, Generator, Tuple, TypeVar

import construct
import yara
from construct import Seek, Struct, this

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
        self.memory_list = self._get_dir(MINIDUMP_STREAM_TYPE.MemoryListStream)
        self.memory64_list = self._get_dir(MINIDUMP_STREAM_TYPE.Memory64ListStream)

    def _get_dir(self, dir_type: T) -> T | None:
        # print(self._dump.Dirs)
        return next(
            (dir for dir in self.dump.Dirs if int(dir.StreamType) == dir_type),
            None,
        )

    def find_section(self, address: int):
        """Finds the section of memory where the address lives"""
        for section in self.memory64_list.Data.MemoryRanges:
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
            for section in self.memory64_list.Data.MemoryRanges:
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
