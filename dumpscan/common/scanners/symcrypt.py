import binascii
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from struct import unpack

import yara
from construct import Array, BytesInteger, Int32ul
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import (
    DSAParameterNumbers,
    DSAPrivateNumbers,
    DSAPublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
    rsa_recover_prime_factors,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from rich import inspect
from rich import print as rprint
from rich.console import Console, ConsoleOptions, RenderResult

from ...common.structs import *
from ...minidump.minidumpfile import MinidumpFile
from ...minidump.structs.MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64
from ..output import get_dumpscan_table
from ..rules import YARA_RULES
from .x509 import x509Scanner


@dataclass
class SymcryptResult:
    address: str
    size: str
    hasPrivateKey: int
    modulus: int
    match: str


class SymcryptScanner:
    def __init__(
        self, minidumpfile: MinidumpFile, x509_scanner: x509Scanner, output: Path
    ) -> None:
        self.rules = yara.compile(sources=YARA_RULES["symcrypt"])
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
        table.add_column("HasPrivateKey")
        table.add_column("Public Bytes (First 20 bytes)", style="bold #f9c300")
        table.add_column("Matching Certificate")
        for rule, objects in self.matching_objects.items():
            for object in objects:
                table.add_row(rule, *map(str, asdict(object).values()))
        yield table

    @classmethod
    def minidump_scan(
        cls, minidumpfile: MinidumpFile, x509_scanner: x509Scanner, output: Path
    ) -> "SymcryptScanner":
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
        parsing_functions = {"rsa": self._parse_rsakey, "dsa": self._parse_dsakey}

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
        physical_address = self.current_section.StartOfMemoryRange + offset

        # The expected size of the structure is 0x28 in length
        mscrypt_rsakey = MSCRYPT_RSAKEY.parse(
            self.dump.read_section(self.current_section, offset, 0x28)
        )
        key_size = unpack("I", self.dump.read_physical(mscrypt_rsakey.pKey, 4))[0]
        key = SYMCRYPT_RSAKEY.parse(
            self.dump.read_physical(mscrypt_rsakey.pKey, key_size)
        )

        # Get the cbSize of modulus (pmModulus + 8) then parse into Modulus struct
        modulus_size = unpack("I", self.dump.read_physical(key.pmModulus + 8, 4))[0]
        modulus = SYMCRYPT_MODULUS.parse(
            self.dump.read_physical(key.pmModulus, modulus_size)
        )

        mod_str = format(modulus.divisor.int.fdef, "X")
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

            if key.hasPrivateKey and self.output:
                # We could write extra code to parse each of the primes but we need to get the private exponent (d) anyway
                # So less work to just pull private exponent and derive the primes from n,e,d
                private_exp_size = unpack(
                    "I", self.dump.read_physical(key.piPrivExps[0] + 8, 4)
                )[0]
                private_exp_modulus = SYMCRYPT_INT.parse(
                    self.dump.read_physical(key.piPrivExps[0], private_exp_size)
                )

                private_exp_hexstr = format(private_exp_modulus.fdef, "X")

                # Get p and q from modulus, public exponent, and private exponent
                d = int(private_exp_hexstr, 16)  # Private exponent
                n = modulus.divisor.int.fdef  # Modulus
                e = key.au64PubExp  # Public exponent
                p, q = rsa_recover_prime_factors(n, e, d)

                # fmt: on

                # We need to create the public numbers to pass to the private numbers
                # All of these numbers exist in the parsed Structs, but easier to call helper functions
                public_numbers = RSAPublicNumbers(e, n)
                private_numbers = RSAPrivateNumbers(
                    p=p,
                    q=q,
                    d=d,
                    dmp1=rsa_crt_dmp1(d, p),
                    dmq1=rsa_crt_dmq1(d, q),
                    iqmp=rsa_crt_iqmp(p, q),
                    public_numbers=public_numbers,
                )
                private_key = private_numbers.private_key()
                if matching_cert:
                    pfx = serialize_key_and_certificates(
                        thumbprint.encode(),
                        private_key,
                        matching_cert,
                        None,
                        NoEncryption(),
                    )
                    filename = thumbprint + "_"
                    filename += (
                        matching_cert.subject._attributes[-1]
                        ._attributes[-1]
                        .value.strip('*."/[]:;|,')
                        .split("/")[0]
                    )
                    with open(f"{self.output / filename}.pfx", "wb") as f:
                        f.write(pfx)

        return SymcryptResult(
            hex(physical_address),
            key.nBitsOfModulus,
            key.hasPrivateKey,
            mod_str[:40],
            matching_cert_value,
        )

    def _parse_dsakey(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset = match[0]
        physical_address = self.current_section.StartOfMemoryRange + offset
        mscrypt_dsakey = MSCRYPT_DSAKEY.parse(
            self.dump.read_section(self.current_section, offset, 0x30)
        )

        # DL GROUP points to P, Q, and G
        dlgroup_size = unpack("I", self.dump.read_physical(mscrypt_dsakey.pDlGroup, 4))[
            0
        ]
        dlgroup = SYMCRYPT_DLGROUP.parse(
            self.dump.read_physical(mscrypt_dsakey.pDlGroup, dlgroup_size)
        )

        p_modulus_size = unpack("I", self.dump.read_physical(dlgroup.pmP + 8, 4))[0]
        primeP = SYMCRYPT_MODULUS.parse(
            self.dump.read_physical(dlgroup.pmP, p_modulus_size)
        )

        q_modulus_size = unpack("I", self.dump.read_physical(dlgroup.pmQ + 8, 4))[0]
        primeQ = SYMCRYPT_MODULUS.parse(
            self.dump.read_physical(dlgroup.pmQ, q_modulus_size)
        )

        # The length of the generator is the same as the length of the key/primeP.
        genG = BytesInteger(mscrypt_dsakey.KeyLength).parse(
            self.dump.read_physical(dlgroup.peG, p_modulus_size)
        )
        print(genG)
        dl_key = SYMCRYPT_DLKEY.parse(self.dump.read_physical(mscrypt_dsakey.pKey, 40))

        # Length of the public key is the same as the length of P prime
        publickey_ints = BytesInteger(dlgroup.cbPrimeP).parse(
            self.dump.read_physical(dl_key.pePublicKey, dlgroup.cbPrimeP)
        )

        mod_str = format(publickey_ints, "X")
        matching_cert = None
        matching_cert_value = ""

        if dl_key.fHasPrivateKey:
            print(mscrypt_dsakey)
            print(dlgroup)
            print(dl_key)
            private_key_size = unpack(
                "I", self.dump.read_physical(dl_key.piPrivateKey + 8, 4)
            )[0]
            privatekey = SYMCRYPT_INT.parse(
                self.dump.read_physical(dl_key.piPrivateKey, private_key_size)
            )
            pk_str = format(privatekey.fdef, "X")

            print(primeP)
            print(privatekey)

            rprint(
                "\n[green]Q: Parsed value[/]",
                len(format(primeQ.divisor.int.fdef, "X")) // 2,
                format(primeQ.divisor.int.fdef, "X"),
                primeQ.divisor.int.fdef,
            )
            rprint(
                "\n[green]P: Parsed value[/]",
                len(format(primeP.divisor.int.fdef, "X")) // 2,
                format(primeP.divisor.int.fdef, "X"),
                primeP.divisor.int.fdef,
            )
            rprint(
                "\n[green]Y: Parsed value[/]",
                len(mod_str) // 2,
                mod_str,
                int(mod_str, 16),
            )
            rprint(
                "\n[green]G: Parsed value[/]",
                len(format(genG, "X")) // 2,
                format(genG, "X"),
                genG,
            )

            # print(pk_str)
            # print(int(pk_str, 16))
        # Zfill is important here for alignment
        # Additionally, we have to read the list of integers (def) backwards

        if self.x509:
            if matching_cert := self.x509.modulus_dict.get(mod_str):
                thumbprint = (
                    binascii.hexlify(matching_cert.fingerprint(hashes.SHA1()))
                    .upper()
                    .decode()
                )
                subject = matching_cert.subject.rfc4514_string()
                matching_cert_value = f"[green]{thumbprint}[/green] -> {subject}"

        return SymcryptResult(
            hex(physical_address),
            dlgroup.nBitsOfP,
            dl_key.fHasPrivateKey,
            mod_str,
            matching_cert_value,
        )
