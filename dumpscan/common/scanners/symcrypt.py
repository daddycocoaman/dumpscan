import binascii
from base64 import b64encode
from collections import defaultdict
from dataclasses import asdict, dataclass
from struct import unpack
from typing import Dict

import yara
from rich import inspect
from rich.console import Console, ConsoleOptions, RenderResult

from ...common.structs import *
from ...minidump.minidumpfile import MinidumpFile
from ...minidump.structs.MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64
from ..output import get_dumpscan_table
from ..rules import YARA_RULES
from .x509 import x509Scanner


@dataclass
class SymcryptRSAResult:
    hasPrivateKey: int
    modulus: int
    match: str


class SymcryptScanner:
    def __init__(
        self, minidumpfile: MinidumpFile, x509_scanner: x509Scanner = None
    ) -> None:
        self.rules = yara.compile(sources=YARA_RULES["symcrypt"])
        self.dump = minidumpfile
        self.x509 = x509_scanner
        self.matching_objects = defaultdict(list)
        self.modulus_dict = {}
        self.public_private_matches = {}
        self.current_section: MINIDUMP_MEMORY_DESCRIPTOR64 = None

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:

        # RSA key results
        table = get_dumpscan_table()
        table.add_column("Rule")
        table.add_column("HasPrivateKey")
        table.add_column("Modulus (First 20 bytes)")
        table.add_column("Matching Certificate")
        for result in self.matching_objects.get("rsa", []):
            table.add_row("rsa", *map(str, asdict(result).values()))
        yield table

    @classmethod
    def minidump_scan(
        cls, minidumpfile: MinidumpFile, x509_scanner: x509Scanner
    ) -> "SymcryptScanner":
        scanner = cls(minidumpfile, x509_scanner)
        for section, data in minidumpfile.read_all_memory64():
            scanner.current_section = section
            scanner.rules.match(
                data=data,
                callback=scanner.parse_yara_match,
                which_callbacks=yara.CALLBACK_MATCHES,
            )

        return scanner

    def parse_yara_match(self, data):
        parsing_functions = {"rsa": self._parse_rsakey}

        rule = data["rule"]
        matching_objects = []

        if parse_func := parsing_functions.get(rule):
            for match in data["strings"]:
                if obj := parse_func(match, rule):
                    matching_objects.append(obj)

        self.matching_objects[rule].extend(matching_objects)
        return yara.CALLBACK_CONTINUE

    def _parse_rsakey(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset = match[0]

        # The expected size of the structure is 0x28 in length
        bcrypt_rsakey = BCRYPT_RSAKEY.parse(
            self.dump.read_section(self.current_section, offset, 0x28)
        )
        key_size = unpack("I", self.dump.read_physical(bcrypt_rsakey.pKey, 4))[0]
        key = SYMCRYPT_RSAKEY.parse(
            self.dump.read_physical(bcrypt_rsakey.pKey, key_size)
        )

        # Get the cbSize of modulus (pmModulus + 8) then parse into Modulus struct
        modulus_size = unpack("I", self.dump.read_physical(key.pmModulus + 8, 4))[0]
        modulus = SYMCRYPT_MODULUS.parse(
            self.dump.read_physical(key.pmModulus, modulus_size)
        )

        # Zfill is important here for alignment
        # Additionally, we have to read the list of integers (def) backwards
        mod_str = "".join(
            [format(i, "x").zfill(8) for i in modulus.divisor.int.fdef[::-1]]
        ).upper()
        matching_cert = None

        if key.hasPrivateKey:
            matching_cert = self.x509.modulus_dict.get(mod_str, None)

        return SymcryptRSAResult(key.hasPrivateKey, mod_str[:40], matching_cert)
