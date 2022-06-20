import logging
import warnings
from struct import unpack
from typing import Dict, List

import yara
from construct import Array, Const, Hex, Int32sl, Int32ul, Int64ul, Struct, Union, this
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicKey,
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
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import Certificate
from rich import inspect
from volatility3.framework import interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows.extensions import EPROCESS
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan

from ...common.structs import *
from .dumpcerts import Dumpcerts

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

log = logging.getLogger("rich")

# fmt: off
def get_yara_rules():
    sources = {}

    # Follow the start of the BCRYPT_RSAKEY Struct
    sources["symcrypt_rsa_key"] = "rule symcrypt_rsa_key {strings: $a = {28 00 00 00 4b 52 53 4d ?? ?? ?? ?? 00 (08 | 0c | 10) 00 00 01} condition: $a}"

    return yara.compile(sources=sources)
# fmt: on


class Symcrypt(interfaces.plugins.PluginInterface):
    """Dump symcrypt keys"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel Layer",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="vadyarascanner", plugin=vadyarascan.VadYaraScan, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="dumpcerts", plugin=Dumpcerts, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="name",
                element_type=str,
                description="Process name to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="matches",
                description="List of modulus to compare to start of private key to match",
                default=[],
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump PFX when a match is found",
                default=False,
                optional=True,
            ),
        ]

    def _generator(self):

        kernel = self.context.modules[self.config["kernel"]]
        pid_list = self.config.get("pid", [])
        name_list = self.config.get("name", [])

        def proc_name_and_pid_filter(proc: EPROCESS):
            if not pid_list and not name_list:
                return False

            if proc.is_valid() and proc.UniqueProcessId:
                try:
                    proc_name = proc.ImageFileName.cast(
                        "string",
                        max_length=proc.ImageFileName.vol.count,
                        errors="ignore",
                    ).lower()
                    return (
                        proc.UniqueProcessId not in pid_list
                        and proc_name not in name_list
                    )
                # Specifically, if there is a smear, process info might not be valid
                # So ignore if the process name can't be cast to anything
                except:
                    return True
            else:
                return True

        filter_func = proc_name_and_pid_filter
        output = self.config.get("dump")
        modulus_matches = self.config.get("matches")
        # Get all the processes
        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            # If process can't be added, just ignore it
            try:
                layer_name = proc.add_process_layer()
            except:
                continue

            layer = self.context.layers[layer_name]
            proc_name = proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace",
            )

            # This will hold all of the public certificates to match against if a hit occurs
            public_certs: Dict[str, Certificate] = {}

            for offset, rule_name, _, _ in layer.scan(
                context=self.context,
                scanner=yarascan.YaraScanner(rules=get_yara_rules()),
                sections=vadyarascan.VadYaraScan.get_vad_maps(proc),
            ):
                # If there is a match for key, then...
                # Get all of the public certs in the process
                # Keep track of modulus and cert object
                if not public_certs:
                    for _, _, _, cert in Dumpcerts.get_certs_by_process(
                        context=self.context,
                        proc=proc,
                        key_types="public",
                    ):
                        try:
                            # If an RSA key, grab the modulus and convert it to a string
                            if isinstance(cert.public_key(), RSAPublicKey):
                                public_certs[
                                    format(cert.public_key().public_numbers().n, "x")
                                ] = cert
                        except:
                            continue

                # Make the bcrypt_RSA_KEY structure to get the pointer to key
                bcrypt_rsakey = BCRYPT_RSAKEY.parse(layer.read(offset, 0x28))

                # Parse the key into a SYMCRYPT_RSA_KEY struct
                # If we can't, just move on
                try:
                    key_total_size = unpack("I", layer.read(bcrypt_rsakey.pKey, 4))[0]
                    key = SYMCRYPT_RSAKEY.parse(
                        layer.read(bcrypt_rsakey.pKey, key_total_size)
                    )
                except Exception as e:
                    yield 0, (
                        format_hints.Hex(offset),
                        proc.UniqueProcessId,
                        proc_name,
                        rule_name,
                        -1,
                        f"Corrupt - {e}",
                    )
                    continue

                # Get the cbSize of modulus (pmModulus + 8) then parse into Modulus struct
                modulus_size = unpack("I", layer.read(key.pmModulus + 8, 4))[0]
                modulus = SYMCRYPT_MODULUS.parse(
                    layer.read(key.pmModulus, modulus_size)
                )

                # Zfill is important here for alignment
                # Additionally, we have to read the list of integers (def) backwards
                mod_str = "".join(
                    [format(i, "x").zfill(8) for i in modulus.divisor.int.fdef[::-1]]
                )

                # Look for a matching cert in the process. If one is found, print thumbprint and subject
                match_string = ""
                matching_cert = public_certs.get(mod_str, None)
                if matching_cert:
                    thumbprint = "".join(
                        "{:02X}".format(b)
                        for b in matching_cert.fingerprint(hashes.SHA1())
                    )

                    subject = matching_cert.subject.rfc4514_string()
                    match_string = f"[green]| MATCH |[/] {thumbprint} | {subject}"
                else:
                    # If there's no matching cert, then print out first 40 bytes of modulus
                    # Check to see if modulus matches what user requests
                    if modulus_matches:
                        for modulus in modulus_matches:
                            if mod_str.upper().startswith(modulus.upper()):
                                match_string = f"[green]| MATCH |[/] {modulus}"

                # If match_string is still empty, use current cert modulus
                if not match_string:
                    match_string = mod_str[:80].upper()

                # If there is a matching cert and there is a private key, make PFX or print pem!
                if key.hasPrivateKey and output:
                    # fmt: off

                    # We could write extra code to parse each of the primes but we need to get the private exponent (d) anyway
                    # So less work to just pull private exponent and derive the primes from n,e,d
                    private_exp_size = unpack("I", layer.read(key.piPrivExps[0] + 8, 4))[0]
                    private_exp_modulus = SYMCRYPT_INT.parse(
                        layer.read(key.piPrivExps[0], private_exp_size)
                    )
                    private_exp_hexstr = "".join(
                        [format(i, "x").zfill(8) for i in private_exp_modulus.fdef[::-1]]
                    )

                    # Get p and q from modulus, public exponent, and private exponent
                    d = int(private_exp_hexstr, 16) # Private exponent
                    n = int(mod_str, 16)            # Modulus
                    e = key.au64PubExp              # Public exponent
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
                        with self.open(f"{thumbprint}.pfx") as f:
                            f.write(pfx)
                    else:
                        with self.open(f"{mod_str[:80].upper()}.cer") as f:
                            f.write(
                                private_key.private_bytes(
                                    encoding=Encoding.DER,
                                    format=PrivateFormat.PKCS8,
                                    encryption_algorithm=NoEncryption(),
                                )
                            )

                yield 0, (
                    format_hints.Hex(offset),
                    proc.UniqueProcessId,
                    proc_name,
                    rule_name,
                    key.hasPrivateKey,
                    match_string,
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                (f'{"Offset":<8}', format_hints.Hex),
                ("PID", int),
                (f'{"Process":<8}', str),
                ("Rule", str),
                ("HasPrivateKey", int),
                ("Details", str),
            ],
            self._generator(),
        )
