import binascii
from base64 import b64encode
from struct import unpack
from typing import Dict, List

import yara
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, load_der_x509_certificate
from minidump.common_structs import MinidumpMemorySegment
from minidump.minidumpreader import (
    MinidumpBufferedMemorySegment,
    MinidumpBufferedReader,
    MinidumpFileReader,
    VirtualSegment,
)
from rich import print as rprint

from ..common.structs import *


class _MinidumpBufferedMemorySegment(MinidumpBufferedMemorySegment):
    def read(self, file_handle, start, end):

        if start > self.end_address:
            return None

        for chunk in self.chunks:
            if chunk.inrange(start, end):
                return chunk.data[start - chunk.start : end - chunk.start]

        if self.total_size <= 2 * self.chunksize:
            chunksize = self.total_size
            vs = VirtualSegment(0, chunksize, self.start_file_address)
            file_handle.seek(self.start_file_address)
            vs.data = file_handle.read(chunksize)
            data = vs.data[start - vs.start : end - vs.start]
            self.chunks.append(vs)
            return vs.data
        else:

            chunksize = max((end - start), self.chunksize)
            if start + chunksize > self.end_address:
                chunksize = self.end_address - start

            # Ensure chunk size is positive
            if chunksize >= 0:
                vs = VirtualSegment(start, start + chunksize, self.start_file_address)
                file_handle.seek(vs.start_file_address)
                vs.data = file_handle.read(chunksize)
                self.chunks.append(vs)
                data = vs.data[start - vs.start : end - vs.start]
                return data


class _MinidumpBufferedReader(MinidumpBufferedReader):
    def _select_segment(self, requested_position):
        # check if we have semgnet for requested address in cache
        for memory_segment in self.memory_segments:
            if memory_segment.inrange(requested_position):
                self.current_segment = memory_segment
                self.current_position = requested_position
                return

        # not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
        for memory_segment in self.reader.memory_segments:
            if memory_segment.inrange(requested_position):
                newsegment = _MinidumpBufferedMemorySegment(
                    memory_segment,
                    self.reader.file_handle,
                    chunksize=self.segment_chunk_size,
                )
                self.memory_segments.append(newsegment)
                self.current_segment = newsegment
                self.current_position = requested_position
                return

    def read_to_end(self, chunksize: int):
        """
        Returns data bytes of size size from the current segment.
        """
        start_address = self.current_segment.start_address
        next_position = start_address + chunksize

        while data := self.current_segment.read(
            self.reader.file_handle,
            start_address,
            next_position,
        ):
            start_address = next_position
            next_position = start_address + chunksize

            yield data

    def yara_search(self, rules: Dict, **kwargs) -> dict:
        """Search memory segments using yara

        Args:
            rules (Rules | Dict): Compiled rules or dictionary of rules used for searching
        """

        # Handle expected kwargs
        self._public_certs: List[Certificate] = kwargs.get("public_certs", None)

        rules = yara.compile(sources=rules)

        # To avoid parsing the same objects
        self._visited_addr = []

        # To hold matching objects
        self._matching_objects = {}

        for segment in self.reader.memory_segments:
            segment: MinidumpMemorySegment

            self.move(segment.start_virtual_address)
            for data in self.read_to_end(self.segment_chunk_size):
                matches = rules.match(
                    data=data,
                    callback=self.parse_yara_match,
                    which_callbacks=yara.CALLBACK_MATCHES,
                )
        return self._matching_objects

    def parse_yara_match(self, data):

        parsing_functions = {
            "x509": self._parse_x509_and_pkcs,
            "pkcs": self._parse_x509_and_pkcs,
            "symcrypt": self._parse_symcrypt,
        }
        matching_objects = []

        rule = data["rule"]
        if rule == "symcrypt":
            print(data)

        for match in data["strings"]:
            addr = (
                self.current_segment.start_address + match[0]
            )  # match[0] is the offset
            # if addr in self._visited_addr:
            #     continue

            self._visited_addr.append(self.current_segment.start_address + match[0])
            if obj := parsing_functions[rule](match, rule):
                matching_objects.append(obj)

        self._matching_objects[data["rule"]] = matching_objects
        return yara.CALLBACK_CONTINUE

    def _parse_x509_and_pkcs(self, match: tuple, rule: str):

        _, cert_size = unpack(">HH", match[2][:4])  # Only need first four bytes
        offset = match[0]
        total_size = offset + cert_size + 4

        cert_data = self.current_segment.read(
            self.reader.file_handle, match[0], total_size
        )

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

    def _parse_symcrypt(self, match: tuple, rule: str):

        # We need to move back here in the end
        original_segment = self.current_segment

        # Get the bcrypt structure
        bcrypt_rsa = BCRYPT_RSAKEY.parse(
            self.current_segment.read(
                self.reader.file_handle, match[0], match[0] + 0x28
            )
        )
        print(hex(match[0]))
        print(bcrypt_rsa)

        # Move to where the pKey points to
        self.move(bcrypt_rsa.pKey)
        key_segment = self.current_segment

        print(hex(self.current_segment.start_address), hex(self.current_position))

        # TODO: Fix read() later to not return entire chunk size
        data = self.current_segment.read(
            self.reader.file_handle,
            bcrypt_rsa.pKey - self.current_segment.start_address,
            bcrypt_rsa.pKey - self.current_position + 4,
        )
        print(hex(self.current_segment.start_address), hex(self.current_position))
        print(data[:64])

        # print(binascii.hexlify(data))
        key_total_size = unpack("I", data[:4])[0]

        # Make the SYMCRYPT key
        key = SYMCRYPT_RSAKEY.parse(
            self.current_segment.read(
                self.reader.file_handle,
                bcrypt_rsa.pKey - self.current_segment.start_address,
                bcrypt_rsa.pKey - self.current_segment.start_address + key_total_size,
            )
        )
        print(key)

        # Move to where key.pmModulus points
        self.move(key.pmModulus)
        modulus_segment = self.current_segment
        modulus_total_size = unpack(
            "I",
            self.current_segment.read(
                self.reader.file_handle,
                key.pmModulus - self.current_segment.start_address + 8,
                key.pmModulus - self.current_segment.start_address + 12,
            )[:4],
        )[0]

        # Read the modulus object
        modulus = SYMCRYPT_MODULUS.parse(
            self.current_segment.read(
                self.reader.file_handle,
                key.pmModulus - self.current_segment.start_address,
                key.pmModulus - self.current_segment.start_address + modulus_total_size,
            )
        )
        mod_str = "".join(
            [format(i, "x").zfill(8) for i in modulus.divisor.int.fdef[::-1]]
        )
        matching_cert = self._public_certs.get(mod_str, None)
        if matching_cert:
            thumbprint = "".join(
                "{:02X}".format(b) for b in matching_cert.fingerprint(hashes.SHA1())
            )

            subject = matching_cert.subject.rfc4514_string()
            match_string = f"{thumbprint} | {subject}"
        else:
            # If there's no matching cert, then print out first 40 bytes of modulus
            match_string = mod_str[:80].upper()

        # Move back to original section!
        self.move(original_segment.start_address)
        print(key.hasPrivateKey)
        return key.hasPrivateKey


class YaraMinidumpFileReader(MinidumpFileReader):
    def get_yara_buffered_reader(self):
        # Setting the chunk size to 16MB
        return _MinidumpBufferedReader(self, 0x1000000)
