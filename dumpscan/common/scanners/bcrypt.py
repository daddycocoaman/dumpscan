import binascii
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from struct import unpack
from construct import Array, Int32ul, SelectError

import yara
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
    rsa_recover_prime_factors,
)
from cryptography.hazmat.primitives.asymmetric.dsa import (
    DSAParameterNumbers,
    DSAPublicNumbers,
    DSAPrivateNumbers,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from rich import inspect, print as rprint
from rich.console import Console, ConsoleOptions, RenderResult

from ...common.structs import *
from ...minidump.minidumpfile import MinidumpFile
from ...minidump.structs.MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64
from ..output import get_dumpscan_table
from ..rules import YARA_RULES
from .x509 import x509Scanner


@dataclass
class BcryptResult:
    address: str
    size: int
    modulus: str
    match: str


class BcryptScanner:
    def __init__(
        self, minidumpfile: MinidumpFile, x509_scanner: x509Scanner, output: Path
    ) -> None:
        self.rules = yara.compile(sources=YARA_RULES["bcrypt"])
        self.dump = minidumpfile
        self.output = output
        self.x509 = x509_scanner
        self.matching_objects = defaultdict(list)
        self.modulus_dict = {}
        self.public_private_matches = {}
        self.current_section: MINIDUMP_MEMORY_DESCRIPTOR64 = None

        if output and not output.exists():
            output.mkdir(parents=True)

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:

        # RSA key results
        table = get_dumpscan_table()
        table.add_column("Rule", style="bold italic #f9c300")
        table.add_column("Address")
        table.add_column("Size")
        table.add_column("Public Bytes (First 20 bytes)", style="bold #f9c300")
        table.add_column("Matching Certificate")
        for rule, objects in self.matching_objects.items():
            for object in objects:
                table.add_row(rule, *map(str, asdict(object).values()))
        yield table

    @classmethod
    def minidump_scan(
        cls, minidumpfile: MinidumpFile, x509_scanner: x509Scanner, output: Path
    ) -> "BcryptScanner":
        scanner = cls(minidumpfile, x509_scanner, output)

        for section, data in minidumpfile.read_all_memory64():
            scanner.current_section = section
            scanner.rules.match(
                data=data,
                callback=scanner.parse_yara_match,
                which_callbacks=yara.CALLBACK_MATCHES,
            )
        return scanner

    def parse_yara_match(self, data):

        rule = data["rule"]
        matching_objects = []

        match rule.split("_")[0]:
            case "rsa":
                parse_func = self._parse_rsakey
            case "dsa":
                parse_func = self._parse_dsakey
            case "ecdh" | "ecdsa":
                parse_func = self._parse_ecckey
            case _:
                return

        if parse_func:
            for match in data["strings"]:
                if obj := parse_func(match, rule):
                    matching_objects.append(obj)

        self.matching_objects[rule].extend(matching_objects)
        return yara.CALLBACK_CONTINUE

    def _parse_rsakey(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset, _, key_type = match
        physical_address = self.current_section.StartOfMemoryRange + offset

        # Because the structures are different per key type, we need to parse
        # the data differently. We need to know the integer sizes.
        try:
            bcrypt_rsablob = BCRYPT_RSAKEY.parse(
                self.dump.read_section(self.current_section, offset, 24)
            )
        except:
            return

        if not bcrypt_rsablob:
            return

        try:
            match key_type:
                case b"RSA1":
                    bcrypt_rsakey = BCRYPT_RSAPUBLIC.parse(
                        self.dump.read_section(
                            self.current_section,
                            offset,
                            24 + bcrypt_rsablob.cbPublicExp + bcrypt_rsablob.cbModulus,
                        )
                    )
                case b"RSA2":
                    bcrypt_rsakey = BCRYPT_RSAPRIVATE.parse(
                        self.dump.read_section(
                            self.current_section,
                            offset,
                            24
                            + bcrypt_rsablob.cbPublicExp
                            + bcrypt_rsablob.cbModulus
                            + bcrypt_rsablob.cbPrime1
                            + bcrypt_rsablob.cbPrime2,
                        )
                    )
                case b"RSA3":
                    bcrypt_rsakey = BCRYPT_RSAFULLPRIVATE.parse(
                        self.dump.read_section(
                            self.current_section,
                            offset,
                            24
                            + bcrypt_rsablob.cbPublicExp
                            + bcrypt_rsablob.cbModulus
                            + (bcrypt_rsablob.cbPrime1 + bcrypt_rsablob.cbPrime2) * 2
                            + bcrypt_rsablob.cbPrime1
                            + bcrypt_rsablob.cbModulus,
                        )
                    )
                case _:
                    return
        except:
            return

        mod_str = format(bcrypt_rsakey.Modulus, "X")
        matching_cert_value = ""

        if self.x509:
            if matching_cert := self.x509.modulus_dict.get(mod_str):
                thumbprint = (
                    binascii.hexlify(matching_cert.fingerprint(hashes.SHA1()))
                    .upper()
                    .decode()
                )
                subject = matching_cert.subject.rfc4514_string()
                matching_cert_value = f"[green]{thumbprint}[/green] -> {subject}"

                # if key_type in [b"RSA2", b"RSA3"] and self.output:
                #     # We could write extra code to parse each of the primes but we need to get the private exponent (d) anyway
                #     # So less work to just pull private exponent and derive the primes from n,e,d
                #     private_exp_size = unpack(
                #         "I", self.dump.read_physical(key.piPrivExps[0] + 8, 4)
                #     )[0]
                #     private_exp_modulus = SYMCRYPT_INT.parse(
                #         self.dump.read_physical(key.piPrivExps[0], private_exp_size)
                #     )

                #     private_exp_hexstr = format(private_exp_modulus.fdef, "X")

                #     # Get p and q from modulus, public exponent, and private exponent
                #     d = int(private_exp_hexstr, 16)  # Private exponent
                #     n = modulus.divisor.int.fdef  # Modulus
                #     e = key.au64PubExp  # Public exponent
                #     p, q = rsa_recover_prime_factors(n, e, d)

                #     # fmt: on

                #     # We need to create the public numbers to pass to the private numbers
                #     # All of these numbers exist in the parsed Structs, but easier to call helper functions
                #     public_numbers = RSAPublicNumbers(e, n)
                #     private_numbers = RSAPrivateNumbers(
                #         p=p,
                #         q=q,
                #         d=d,
                #         dmp1=rsa_crt_dmp1(d, p),
                #         dmq1=rsa_crt_dmq1(d, q),
                #         iqmp=rsa_crt_iqmp(p, q),
                #         public_numbers=public_numbers,
                #     )
                #     private_key = private_numbers.private_key()
                #     if matching_cert:
                #         pfx = serialize_key_and_certificates(
                #             thumbprint.encode(),
                #             private_key,
                #             matching_cert,
                #             None,
                #             NoEncryption(),
                #         )
                #         filename = thumbprint + "_"
                #         filename += (
                #             matching_cert.subject._attributes[-1]
                #             ._attributes[-1]
                #             .value.strip('*."/[]:;|,')
                #             .split("/")[0]
                #         )
                #         with open(f"{self.output / filename}.pfx", "wb") as f:
                #             f.write(pfx)
        return BcryptResult(
            hex(physical_address),
            str(bcrypt_rsablob.BitLength),
            mod_str[:40],
            matching_cert_value,
        )

    def _parse_dsakey(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset, _, key_type = match
        physical_address = self.current_section.StartOfMemoryRange + offset

        # Because the structures are different per key type, we need to parse
        # the data differently. We need to know the integer sizes.
        try:
            bcrypt_dsablob = BCRYPT_DSAKEY_V2.parse(
                self.dump.read_section(self.current_section, offset, 28)
            )
        except:
            return

        if not bcrypt_dsablob:
            return

        try:
            match key_type:
                case b"DPB2":
                    bcrypt_dsakey = BCRYPT_DSAPUBLIC.parse(
                        self.dump.read_section(
                            self.current_section,
                            offset,
                            28
                            + bcrypt_dsablob.cbSeedLength
                            + bcrypt_dsablob.cbGroupSize
                            + bcrypt_dsablob.cbKey * 3,
                        )
                    )
                case b"DPV2":
                    bcrypt_dsakey = BCRYPT_DSAPRIVATE.parse(
                        self.dump.read_section(
                            self.current_section,
                            offset,
                            28
                            + bcrypt_dsablob.cbSeedLength
                            + bcrypt_dsablob.cbGroupSize
                            + bcrypt_dsablob.cbKey * 3
                            + bcrypt_dsablob.cbGroupSize,
                        )
                    )
                case _:
                    return
        except:
            return

        mod_str = format(bcrypt_dsakey.Public, "X")
        matching_cert = None
        matching_cert_value = ""

        if self.x509:
            if matching_cert := self.x509.modulus_dict.get(mod_str):
                thumbprint = (
                    binascii.hexlify(matching_cert.fingerprint(hashes.SHA1()))
                    .upper()
                    .decode()
                )
                subject = matching_cert.subject.rfc4514_string()
                matching_cert_value = f"[green]{thumbprint}[/green] -> {subject}"

        return BcryptResult(
            hex(physical_address),
            str(bcrypt_dsablob.cbKey * 8),
            mod_str[:40],
            matching_cert_value,
        )

    def _parse_ecckey(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset, _, key_type = match
        physical_address = self.current_section.StartOfMemoryRange + offset

        # Because the structures are different per key type, we need to parse
        # the data differently. We need to know the integer sizes.
        try:
            bcrypt_eccblob = BCRYPT_ECCKEY.parse(
                self.dump.read_section(self.current_section, offset, 8)
            )
        except:
            return

        if not bcrypt_eccblob:
            return

        try:
            match rule.split("_")[1]:
                case "public":
                    bcrypt_ecckey = BCRYPT_ECCPUBLIC.parse(
                        self.dump.read_section(
                            self.current_section, offset, 8 + bcrypt_eccblob.cbKey * 2
                        )
                    )
                case "private":
                    bcrypt_ecckey = BCRYPT_ECCPRIVATE.parse(
                        self.dump.read_section(
                            self.current_section, offset, 8 + bcrypt_eccblob.cbKey * 3
                        )
                    )
                case _:
                    return
        except:
            return

        public_ints = (format(bcrypt_ecckey.X, "X"), format(bcrypt_ecckey.Y, "X"))
        matching_cert = None
        matching_cert_value = ""

        if self.x509:
            if matching_cert := self.x509.modulus_dict.get(public_ints):
                thumbprint = (
                    binascii.hexlify(matching_cert.fingerprint(hashes.SHA1()))
                    .upper()
                    .decode()
                )
                subject = matching_cert.subject.rfc4514_string()
                matching_cert_value = f"[green]{thumbprint}[/green] -> {subject}"

        return BcryptResult(
            hex(physical_address),
            rule.split("_")[2].strip("P"),
            f"X: {public_ints[0][:40]} | Y: {public_ints[1][:40]}",
            matching_cert_value,
        )
