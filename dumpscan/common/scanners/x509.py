import binascii
from base64 import b64encode
from collections import defaultdict
from struct import unpack

import yara
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, load_der_x509_certificate
from rich import inspect
from rich.console import Console, ConsoleOptions, RenderResult
from rich.table import Table

from ...minidump.minidumpfile import MinidumpFile
from ...minidump.structs.MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64
from ..output import get_dumpscan_table
from ..rules import YARA_RULES


class x509Scanner:
    def __init__(self, minidumpfile: MinidumpFile) -> None:
        self.rules = yara.compile(sources=YARA_RULES["x509"])
        self.dump = minidumpfile
        self.matching_objects = defaultdict(list)
        self.modulus_dict = {}
        self.public_private_matches = {}
        self.current_section: MINIDUMP_MEMORY_DESCRIPTOR64 = None

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:

        table = get_dumpscan_table()
        table.add_column("Rule", style="bold #f9c300")
        table.add_column("Result", style="#008df8")
        table.add_column("Thumbprint", style="#008df8")
        table.add_column("Public Integers (First 20 bytes)")

        for key, values in self.matching_objects.items():
            found_certs = []
            for value in values:
                if isinstance(value, Certificate):
                    thumbprint = (
                        binascii.hexlify(value.fingerprint(hashes.SHA1()))
                        .upper()
                        .decode()
                    )

                    # Clean up output by only printing unique certs
                    if thumbprint in found_certs:
                        continue
                    found_certs.append(thumbprint)

                    public_key = value.public_key()

                    if isinstance(public_key, RSAPublicKey):
                        pubints = format(public_key.public_numbers().n, "x")[
                            :40
                        ].upper()

                    elif isinstance(public_key, EllipticCurvePublicKey):
                        pubints = f"X:{str(public_key.public_numbers().x)[:40]} | Y:{str(public_key.public_numbers().y)[:40]} "

                    table.add_row(
                        key,
                        value.subject.rfc4514_string(),
                        thumbprint,
                        pubints,
                    )
                elif isinstance(value, RSAPrivateKey):
                    result = str(value.key_size)
                    if matching_cert := self.public_private_matches.get(value):
                        result += f"-> {matching_cert.subject.rfc4514_string()}"
                    table.add_row(
                        key,
                        result,
                        None,
                        format(value.private_numbers().public_numbers.n, "x")[
                            :40
                        ].upper(),
                    )
        yield table

    @classmethod
    def minidump_scan(cls, minidumpfile: MinidumpFile) -> "x509Scanner":
        scanner = cls(minidumpfile)
        for section, data in minidumpfile.read_all_memory64():
            scanner.current_section = section
            scanner.rules.match(
                data=data,
                callback=scanner.parse_yara_match,
                which_callbacks=yara.CALLBACK_MATCHES,
            )

        if private_keys := scanner.matching_objects.get("pkcs"):
            scanner.modulus_dict = {}
            for cert in scanner.matching_objects.get("x509"):
                public_key = cert.public_key()
                if isinstance(public_key, RSAPublicKey):
                    pub_modulus_str = format(public_key.public_numbers().n, "x").upper()
                    scanner.modulus_dict[pub_modulus_str] = cert

            for private_key in private_keys:
                priv_modulus_str = format(
                    private_key.private_numbers().public_numbers.n, "x"
                )
                if match := scanner.modulus_dict.get(priv_modulus_str):
                    scanner.public_private_matches[private_key, match]

        return scanner

    def parse_yara_match(self, data):
        rule = data["rule"]
        matching_objects = []

        for match in data["strings"]:
            if obj := self.parse_results(match, rule):
                matching_objects.append(obj)

        self.matching_objects[rule].extend(matching_objects)
        return yara.CALLBACK_CONTINUE

    def parse_results(self, match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset = match[0]

        # Only need first four bytes
        _, cert_size = unpack(">HH", match[2][:4])
        cert_data = self.dump.read_section(self.current_section, offset, cert_size + 4)

        if rule == "x509":
            try:
                return load_der_x509_certificate(cert_data, backend=default_backend())
            except:
                pass
        elif rule == "pkcs":
            pem = (
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                + b64encode(cert_data)
                + b"\n-----END RSA PRIVATE KEY-----"
            )
            try:
                return load_pem_private_key(pem, None, default_backend())
            except:
                pass
