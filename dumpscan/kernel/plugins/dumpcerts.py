import binascii
import warnings
from base64 import b64encode
from struct import unpack
from typing import Callable, Iterable, List, Tuple, Union

import yara
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import Certificate, load_der_x509_certificate
from volatility3.framework import interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows.extensions import EPROCESS
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class Dumpcerts(interfaces.plugins.PluginInterface):
    """Dump public and private RSA keys based on ASN-1 structure"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="vadyarascanner", plugin=vadyarascan.VadYaraScan, version=(1, 0, 0)
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
            requirements.ChoiceRequirement(
                ["all", "private", "public"],
                name="type",
                default="all",
                description="Types of keys to dump",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump", description="Dump keys", default=False, optional=True
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Scan physical memory instead of processes",
                default=False,
                optional=True,
            ),
        ]

    def _save_file(self, data: bytes, filename: str, rule: str):
        ext = ".key" if rule == "pkcs" else ".crt"
        with self.open(f"{filename}{ext}") as f:
            f.write(data)

    @classmethod
    def get_yara_rules(cls, key_type: str):
        sources = {}
        if key_type in ["all", "public"]:
            sources[
                "x509"
            ] = "rule x509 {strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a}"

        if key_type in ["all", "private"]:
            sources[
                "pkcs"
            ] = "rule pkcs {strings: $a = {30 82 ?? ?? 02 01 00} condition: $a}"

        return yara.compile(sources=sources)

    @classmethod
    def get_cert_or_pem(
        self,
        layer: interfaces.layers.DataLayerInterface,
        rule_name: str,
        offset: int,
        value: bytes,
    ) -> Union[Certificate, PRIVATE_KEY_TYPES]:
        """Parse the value from the layer and convert to an X509 cert or PEM.

        Args:
            layer (interfaces.layers.DataLayerInterface): Current layer
            rule_name (str): Rule that triggered the match
            offset (int): Offset address
            value (bytes): Bytes representing a certificate or pem

        Returns:
            Union[Certificate, PRIVATE_KEY_TYPES]: Either a Certificate or PEM type
        """
        try:
            _, cert_size = unpack(">HH", value[0:4])
            data = layer.read(offset, cert_size + 4)

            # If x509 triggered, try to create a DER x509 certificate to validate
            if rule_name == "x509":
                rsa_object = load_der_x509_certificate(data, default_backend())

            # If pkcs triggered, try to create a PEM private key to validate
            elif rule_name == "pkcs":
                pem = (
                    b"-----BEGIN RSA PRIVATE KEY-----\n"
                    + b64encode(data)
                    + b"\n-----END RSA PRIVATE KEY-----"
                )
                rsa_object = load_pem_private_key(pem, None, default_backend())

            return rsa_object
        except:
            return None

    @classmethod
    def get_certs_by_process(
        cls,
        context: interfaces.context.ContextInterface,
        proc: interfaces.objects.ObjectInterface,
        key_types: str,
    ) -> Iterable[
        Tuple[
            int,
            interfaces.objects.ObjectInterface,
            str,
            Union[Certificate, PRIVATE_KEY_TYPES],
        ]
    ]:
        """Gets certificates or pem by process

        Args:
            context (interfaces.context.ContextInterface): Context
            proc (interfaces.objects.ObjectInterface): Process object to scan
            key_types (str): Type of key to scan for

        Yields:
            Iterable[ Tuple[ int, interfaces.objects.ObjectInterface, str, Union[Certificate, PRIVATE_KEY_TYPES], ] ]: Scan results
        """
        layer_name = proc.add_process_layer()
        layer = context.layers[layer_name]

        for offset, rule_name, _, value in layer.scan(
            context=context,
            scanner=yarascan.YaraScanner(rules=cls.get_yara_rules(key_types)),
            sections=vadyarascan.VadYaraScan.get_vad_maps(proc),
        ):
            cert_or_pem = cls.get_cert_or_pem(layer, rule_name, offset, value)
            if cert_or_pem:
                yield (offset, proc, rule_name, cert_or_pem)

    @classmethod
    def get_process_certificates(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: False,
        key_types: str = "all",
    ) -> Iterable[
        Tuple[
            int,
            interfaces.objects.ObjectInterface,
            str,
            Union[Certificate, PRIVATE_KEY_TYPES],
        ]
    ]:
        """Scans processes for RSA certificates

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            filter_func: Filter function for listing processes
            key_types: Can be "all", "public", or "private"

        Yields:
            A tuple of offset, EPROCESS, rule name, and certificate or key found by scanning process layer
        """
        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_func=filter_func,
        ):
            for offset, proc, rule_name, cert_or_pem in cls.get_certs_by_process(
                context, proc, key_types
            ):
                yield (offset, proc, rule_name, cert_or_pem)

    @classmethod
    def get_physical_certificates(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        key_type: str,
    ) -> Iterable[Tuple[int, str, Union[Certificate, PRIVATE_KEY_TYPES],]]:

        layer = context.layers[layer_name]
        for offset, rule_name, _, value in layer.scan(
            context=context,
            scanner=yarascan.YaraScanner(rules=cls.get_yara_rules(key_type)),
        ):
            cert_or_pem = cls.get_cert_or_pem(layer, rule_name, offset, value)
            if cert_or_pem:
                yield (offset, rule_name, cert_or_pem)

    def _generator(self, physical: bool):

        kernel = self.context.modules[self.config["kernel"]]
        pid_list = self.config.get("pid", [])
        name_list = self.config.get("name", [])

        def proc_name_and_pid_filter(proc: EPROCESS):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="ignore",
                ).lower()
                return (
                    proc.UniqueProcessId not in pid_list and proc_name not in name_list
                )
            # Specifically, if there is a smear, process info might not be valid
            # So ignore if the process name can't be cast to anything
            except:
                return True

        if pid_list or name_list:
            filter_func = proc_name_and_pid_filter
        else:
            filter_func = lambda x: False

        key_type = self.config.get("type")
        output = self.config.get("dump", False)

        if physical:

            for offset, rule_name, cert_or_pem in self.get_physical_certificates(
                context=self.context, layer_name=kernel.layer_name, key_type=key_type
            ):
                value, output_bytes, thumbprint = self._get_value_and_bytes(
                    rule_name, cert_or_pem
                )

                if output:
                    if rule_name == "pkcs":
                        self._save_file(output_bytes, value, rule_name)
                    elif rule_name == "x509":
                        filename = thumbprint + "_"
                        filename += (
                            cert_or_pem.subject._attributes[-1]
                            ._attributes[-1]
                            .value.strip('*."/[]:;|,')
                            .split("/")[0]
                        )
                        self._save_file(output_bytes, filename, rule_name)

                yield 0, (
                    format_hints.Hex(offset),
                    rule_name,
                    value,
                )
        else:
            for offset, proc, rule_name, rsa_object in self.get_process_certificates(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
                filter_func=filter_func,
                key_types=key_type,
            ):

                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )

                value, output_bytes, thumbprint = self._get_value_and_bytes(
                    rule_name, rsa_object
                )

                if output:
                    if rule_name == "pkcs":
                        self._save_file(
                            output_bytes, f"{hex(offset)}_{value}", rule_name
                        )
                    elif rule_name == "x509":
                        filename = thumbprint + "_"
                        filename += (
                            rsa_object.subject._attributes[-1]
                            ._attributes[-1]
                            .value.strip('*."/\[]:;|,')
                        )

                        self._save_file(output_bytes, filename, rule_name)

                yield 0, (
                    format_hints.Hex(offset),
                    proc.UniqueProcessId,
                    proc_name,
                    rule_name,
                    thumbprint,
                    value,
                )

    def _get_value_and_bytes(
        self, rule_name: str, rsa_object: Union[Certificate, PRIVATE_KEY_TYPES]
    ) -> Tuple[str, bytes, str]:
        """Helper method to get the value and bytes from a Certificate or PEM

        Args:
            rule_name (str): Rule that triggered the match
            rsa_object (Union[Certificate, PRIVATE_KEY_TYPES]): Certificate or PEM

        Returns:
            Tuple[str, bytes]: Value for output, output bytes for saving to file
        """

        # If x509 triggered, value is equal to subject (or thumbprint if subject fails)
        if rule_name == "x509":

            try:
                value = str(rsa_object.subject.rfc4514_string())
                thumbprint = (
                    binascii.hexlify(rsa_object.fingerprint(hashes.SHA1()))
                    .upper()
                    .decode()
                )
            except:
                pass

            output_bytes = rsa_object.public_bytes(Encoding.DER)

        # If pkcs triggered, value is equal to the key size
        elif rule_name == "pkcs":
            value = str(rsa_object.key_size)
            thumbprint = ""
            output_bytes = rsa_object.private_bytes(
                Encoding.DER,
                PrivateFormat.PKCS8,
                NoEncryption(),
            )

        return (value, output_bytes, thumbprint)

    def run(self) -> renderers.TreeGrid:
        physical = self.config.get("physical")
        if physical:
            return renderers.TreeGrid(
                [
                    (f'{"Offset":<8}', format_hints.Hex),
                    ("Rule", str),
                    ("Thumbprint", str),
                    ("Value", str),
                ],
                self._generator(physical),
            )
        else:
            return renderers.TreeGrid(
                [
                    (f'{"Offset":<8}', format_hints.Hex),
                    ("PID", int),
                    (f'{"Process":<8}', str),
                    ("Rule", str),
                    ("Thumbprint/Key Size", str),
                    ("Value", str),
                ],
                self._generator(physical),
            )
