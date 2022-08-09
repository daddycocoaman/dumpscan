import binascii
from pathlib import Path
from struct import unpack

import yara
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)
from cryptography.x509 import Certificate, load_der_x509_certificate
from rich import inspect, print
from rich.console import Console, ConsoleOptions, RenderResult

from dumpscan.common.scanners.utils import format_thumbprint

from ...minidump.minidumpfile import MinidumpFile
from ...minidump.structs.MinidumpMemory64List import MINIDUMP_MEMORY_DESCRIPTOR64
from ..output import get_dumpscan_table
from ..rules import YARA_RULES


class x509Scanner:
    def __init__(self, minidumpfile: MinidumpFile, output: Path) -> None:
        self.rules = yara.compile(sources=YARA_RULES["x509"])
        self.dump = minidumpfile
        self.output = output
        self.matching_objects = {"x509": [], "pkcs": []}
        self.modulus_dict = {}
        self.public_private_matches = {}
        self.current_section: MINIDUMP_MEMORY_DESCRIPTOR64 = None

        if output and not output.exists():
            output.mkdir(parents=True)

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:

        table = get_dumpscan_table()
        table.add_column("Rule", style="bold #f9c300")
        table.add_column("Type", style="bold #f9c300")
        table.add_column("Result", style="#008df8")
        table.add_column("Thumbprint", style="#008df8")
        table.add_column("Public Ints (20 bytes) || Matching Cert")

        found_certs = set()

        for value in self.matching_objects.get("x509"):
            thumbprint = None

            thumbprint = format_thumbprint(value)

            # Clean up output by only printing unique certs
            if thumbprint in found_certs:
                continue
            found_certs.add(thumbprint)

            public_key = value.public_key()
            key_type = ""

            if isinstance(public_key, RSAPublicKey):
                pubints = "N: " + format(public_key.public_numbers().n, "X")[:40]
                key_type = "RSA"

            elif isinstance(public_key, EllipticCurvePublicKey):
                pubints = f"X: {format(public_key.public_numbers().x, 'X')[:40]} | Y: {format(public_key.public_numbers().y, 'X')[:40]}"
                key_type = "ECC"

            elif isinstance(public_key, DSAPublicKey):
                pubints = "Y: " + format(public_key.public_numbers().y, "X")[:40]
                key_type = "DSA"
            elif isinstance(public_key, Ed448PublicKey):
                pubints = ""
                key_type = "Ed448"
            elif isinstance(public_key, Ed25519PublicKey):
                pubints = ""
                key_type = "Ed25519"

            table.add_row(
                "x509",
                key_type,
                value.subject.rfc4514_string(),
                thumbprint,
                pubints,
            )

        found_keys = []
        for value in self.matching_objects.get("pkcs"):

            if hasattr(value, "private_numbers"):
                private_numbers = value.private_numbers()
                if value.private_numbers() in found_keys:
                    continue
                found_keys.append(private_numbers)

            rule = "pkcs"

            if isinstance(value, RSAPrivateKey):
                result = str(value.key_size)
                thumbprint, cert_subject = self.match_priv_pub_ints(
                    format(value.private_numbers().public_numbers.n, "X")
                )

                table.add_row(rule, "RSA", result, thumbprint, cert_subject)

            elif isinstance(value, DSAPrivateKey):
                result = str(value.key_size)
                thumbprint, cert_subject = self.match_priv_pub_ints(
                    format(value.private_numbers().public_numbers.y, "X")
                )
                table.add_row(rule, "DSA", result, thumbprint, cert_subject)

            elif isinstance(value, EllipticCurvePrivateKey):
                result = str(value.key_size)
                thumbprint, cert_subject = self.match_priv_pub_ints(
                    (
                        format(value.private_numbers().public_numbers.x, "X"),
                        format(value.private_numbers().public_numbers.y, "X"),
                    )
                )
                table.add_row(rule, "ECC", result, thumbprint, cert_subject)
            elif isinstance(value, Ed448PrivateKey):
                thumbprint, cert_subject = self.match_by_verify(value)

                # Key is always 57 bytes
                table.add_row(rule, "Ed448", "57", thumbprint, cert_subject)
            elif isinstance(value, Ed25519PrivateKey):
                thumbprint, cert_subject = self.match_by_verify(value)

                # Key is always 32 bytes
                table.add_row(rule, "Ed25519", "32", thumbprint, cert_subject)
        yield table

    def match_by_verify(
        self, private_key: Ed448PrivateKey | Ed25519PrivateKey
    ) -> tuple[str, str]:

        data = b"dumpscan_verify"
        signature = private_key.sign(data)

        for cert in self.matching_objects.get("x509"):
            if (
                cert.public_key().__class__.__name__
                == private_key.public_key().__class__.__name__
            ):
                try:
                    cert.public_key().verify(signature, data)
                    return format_thumbprint(cert), cert.subject.rfc4514_string()
                except:
                    pass

        return None, None

    def match_priv_pub_ints(self, pubints: str | tuple[str, ...]) -> tuple[str, str]:
        if matching_cert := self.modulus_dict.get(pubints):
            return (
                format_thumbprint(matching_cert),
                matching_cert.subject.rfc4514_string(),
            )
        return None, None

    def save_file(self, data: bytes, filename: str):
        if self.output:
            file = self.output / filename
            with file.open("wb") as f:
                f.write(data)

    @classmethod
    def minidump_scan(cls, minidumpfile: MinidumpFile, output: Path) -> "x509Scanner":
        scanner = cls(minidumpfile, output)

        for section, data in minidumpfile.read_all_memory64():
            scanner.current_section = section
            scanner.rules.match(
                data=data,
                callback=scanner.parse_yara_match,
                which_callbacks=yara.CALLBACK_MATCHES,
            )

        scanner.modulus_dict = {}
        for cert in scanner.matching_objects.get("x509", []):
            try:
                public_key = cert.public_key()
            except:
                inspect(cert, all=True)
                continue
            public_int = None

            if isinstance(public_key, RSAPublicKey):
                public_int = format(public_key.public_numbers().n, "X")
            elif isinstance(public_key, EllipticCurvePublicKey):
                public_int = (
                    format(public_key.public_numbers().x, "X"),
                    format(public_key.public_numbers().y, "X"),
                )
            elif isinstance(public_key, DSAPublicKey):
                public_int = format(public_key.public_numbers().y, "X")

            if public_int:
                scanner.modulus_dict[public_int] = cert

        if private_keys := scanner.matching_objects.get("pkcs"):
            for private_key in private_keys:
                priv_str = None

                if isinstance(private_key, RSAPrivateKey):
                    priv_str = format(
                        private_key.private_numbers().public_numbers.n, "X"
                    )
                elif isinstance(private_key, EllipticCurvePrivateKey):
                    priv_str = (
                        format(private_key.private_numbers().public_numbers.x, "X"),
                        format(private_key.private_numbers().public_numbers.y, "X"),
                    )
                elif isinstance(private_key, DSAPrivateKey):
                    priv_str = format(
                        private_key.private_numbers().public_numbers.y, "X"
                    )

                if priv_str:
                    if match := scanner.modulus_dict.get(priv_str):
                        scanner.public_private_matches[private_key] = match

        return scanner

    def parse_yara_match(self, data):
        rule = data["rule"]
        matching_objects = []

        for match in data["strings"]:
            if obj := self.parse_results(match, rule):
                matching_objects.append(obj)

                if self.output:
                    if rule == "pkcs":
                        output_bytes = obj.private_bytes(
                            Encoding.DER,
                            PrivateFormat.PKCS8,
                            NoEncryption(),
                        )
                        filename = hex(match[0]) + "_" + str(obj.key_size) + ".key"

                    elif rule == "x509":
                        output_bytes = obj.public_bytes(Encoding.DER)
                        thumbprint = (
                            binascii.hexlify(obj.fingerprint(hashes.SHA1()))
                            .upper()
                            .decode()
                        )

                        filename = thumbprint + "_"
                        filename += (
                            obj.subject._attributes[-1]
                            ._attributes[-1]
                            .value.strip('*"/[]:;|,')
                            .split("/")[0]
                        )

                    self.save_file(output_bytes, filename)

        self.matching_objects[rule].extend(matching_objects)
        return yara.CALLBACK_CONTINUE

    def parse_results(self, yara_match: tuple, rule: str):

        # This is the offset from the bytes being scanned
        offset, _, match = yara_match

        # The last digit of the sequence tag is the number of bytes that represent the cert size
        # But if the sequence tag is only 0x30, then the next byte is the cert size
        # To determine, we need to check the split distance of 0x30 to 020100 for pkcs
        if rule == "x509":
            sequence_tag_byte_len = int(binascii.hexlify(match[:2]).decode()[-1])
        elif rule == "pkcs":
            sequence_tag_byte_len = match.index(b"\x02\x01") // 2

        # Assuming no cert size is ever larger than 65535. Right?
        unpack_str = ">B" if sequence_tag_byte_len == 1 else ">H"

        # Need to grab the correct bytes that represent the cert size
        if sequence_tag_byte_len == 1 and rule == "pkcs":
            cert_size = int(match[match.index(b"\x02\x01") - 1])
        else:
            cert_size = unpack(
                unpack_str,
                match[2 : 2 + sequence_tag_byte_len],
            )[0]

        total_size = cert_size + sequence_tag_byte_len + 2

        # if rule == "pkcs":
        #     print(
        #         binascii.hexlify(match),
        #         match.index(b"\x02\x01"),
        #         sequence_tag_byte_len,
        #         cert_size,
        #     )

        cert_data = self.dump.read_section(self.current_section, offset, total_size)
        # if rule == "pkcs" and cert_size < 400:
        #     print(
        #         binascii.hexlify(match),
        #         match.index(b"\x02\x01"),
        #         sequence_tag_byte_len,
        #         cert_size,
        #         binascii.hexlify(cert_data),
        #     )

        if rule == "x509":
            try:
                return load_der_x509_certificate(cert_data, backend=default_backend())
            except:
                pass
        elif rule == "pkcs":
            try:
                return load_der_private_key(cert_data, None, default_backend())
            except:
                pass
