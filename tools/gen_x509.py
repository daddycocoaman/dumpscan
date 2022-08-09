import gc
import os
from binascii import hexlify
from datetime import datetime, timedelta
from decimal import Decimal
from math import pow
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES,
    CERTIFICATE_PRIVATE_KEY_TYPES,
)
from cryptography.x509 import (
    Certificate,
    CertificateBuilder,
    DNSName,
    Name,
    NameAttribute,
    NameOID,
    SubjectAlternativeName,
    random_serial_number,
)
from minidump.utils.createminidump import MINIDUMP_TYPE, create_dump
from oscrypto import asymmetric, backend
from rich import inspect, print
from rich.rule import Rule
from rich.table import Table

SUBJECT_NAME = "dumpscan"
ISSUER = "daddycocoaman.dev"
NOT_BEFORE = datetime.today() - timedelta(1, 0, 0)
NOT_AFTER = datetime.today() + timedelta(30, 0, 0)
SERIAL_NUMBER = random_serial_number()

gc.disable()


def dump(filename: str):
    create_dump(
        os.getpid(),
        (Path(__file__).parents[1] / "samples" / filename).resolve().as_posix(),
        MINIDUMP_TYPE.MiniDumpNormal | MINIDUMP_TYPE.MiniDumpWithFullMemory,
    )


def create_x509Name(name: str) -> Name:
    return Name([NameAttribute(NameOID.COMMON_NAME, name)])


def create_certificate(
    private_key: CERTIFICATE_PRIVATE_KEY_TYPES,
    public_key: CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES,
    algorithm=hashes.SHA256(),
) -> Certificate:
    builder = CertificateBuilder(
        issuer_name=create_x509Name(ISSUER),
        not_valid_before=NOT_BEFORE,
        not_valid_after=NOT_AFTER,
        subject_name=create_x509Name(SUBJECT_NAME + public_key.__class__.__name__),
        serial_number=SERIAL_NUMBER,
    )
    builder = builder.public_key(public_key)
    builder.add_extension(SubjectAlternativeName([DNSName(ISSUER)]), critical=False)
    return builder.sign(private_key, algorithm, default_backend())


def generate_rsa_keypair_and_certificate():
    os_rsa_public, os_rsa_private = asymmetric.generate_pair("rsa", 4096)

    rsa_private_key = serialization.load_pem_private_key(
        asymmetric.dump_private_key(os_rsa_private.asn1, None),
        None,
    )

    rsa_public_key = serialization.load_pem_public_key(
        asymmetric.dump_public_key(os_rsa_public.asn1)
    )

    rsa_certificate = create_certificate(rsa_private_key, rsa_public_key)
    return (
        rsa_certificate,
        rsa_private_key,
        rsa_public_key,
        os_rsa_private,
        os_rsa_public,
    )


def generate_dsa_keypair_and_certificate():
    os_dsa_public, os_dsa_private = asymmetric.generate_pair("dsa", 2048)
    dsa_private_key = serialization.load_pem_private_key(
        asymmetric.dump_private_key(os_dsa_private.asn1, None),
        None,
    )

    dsa_public_key = serialization.load_pem_public_key(
        asymmetric.dump_public_key(os_dsa_public.asn1)
    )

    dsa_certificate = create_certificate(dsa_private_key, dsa_public_key)
    return (
        dsa_certificate,
        dsa_private_key,
        dsa_public_key,
        os_dsa_private,
        os_dsa_public,
    )


def generate_ecc_keypair_and_certificate():
    os_ecc_public, os_ecc_private = asymmetric.generate_pair("ec", curve="secp384r1")

    ecc_private_key = serialization.load_pem_private_key(
        asymmetric.dump_private_key(os_ecc_private.asn1, None),
        None,
    )

    ecc_public_key = serialization.load_pem_public_key(
        asymmetric.dump_public_key(os_ecc_public.asn1)
    )

    ecc_certificate = create_certificate(ecc_private_key, ecc_public_key)

    return (
        ecc_certificate,
        ecc_private_key,
        ecc_public_key,
        os_ecc_private,
        os_ecc_public,
    )


def generate_ed25519_keypair_and_certificate():
    ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_public_key = ed25519_private_key.public_key()

    return (
        create_certificate(ed25519_private_key, ed25519_public_key, algorithm=None),
        ed25519_private_key,
        ed25519_public_key,
    )


def generate_ed448_keypair_and_certificate():
    ed448_private_key = ed448.Ed448PrivateKey.generate()
    ed448_public_key = ed448_private_key.public_key()

    return ed448_private_key, create_certificate(
        ed448_private_key, ed448_public_key, algorithm=None
    )


def get_thumbprint(certificate: Certificate) -> str:
    return hexlify(certificate.fingerprint(hashes.SHA1())).decode().upper()


def dsa_summary(dsa_private_key: dsa.DSAPrivateKey):
    public_numbers = dsa_private_key.public_key().public_numbers()
    param_numbers = dsa_private_key.public_key().parameters().parameter_numbers()
    print(dsa_public.public_numbers())

    q_hex = format(param_numbers.q, "x").upper()
    print("\n[green]Q: Expected value[/]", len(q_hex) // 2, q_hex, param_numbers.q)

    p_hex = format(param_numbers.p, "x").upper()
    print("\n[green]P: Expected value[/]", len(p_hex) // 2, p_hex, param_numbers.p)

    y_hex = format(public_numbers.y, "x").upper()
    print("\n[green]Y: Expected value[/]", len(y_hex) // 2, y_hex, public_numbers.y)

    g_hex = format(param_numbers.g, "x").upper()
    print("\n[green]G: Expected value[/]", len(g_hex) // 2, g_hex, param_numbers.g)


def ecc_summary(
    ecc_public: ec.EllipticCurvePublicKey,
    ecc_private: ec.EllipticCurvePrivateKey,
):
    public_numbers = ecc_public.public_numbers()
    priv_numbers = ecc_private.private_numbers()
    print(public_numbers)
    print(priv_numbers.private_value)


if __name__ == "__main__":
    (
        rsa_cert,
        rsa_priv,
        rsa_public,
        os_rsa_priv,
        os_rsa_public,
    ) = generate_rsa_keypair_and_certificate()
    rsa_bytes = rsa_cert.public_bytes(serialization.Encoding.DER)
    rsa_priv_bytes = rsa_priv.private_bytes(
        serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dump("python_rsa.dmp")

    (
        dsa_cert,
        dsa_priv,
        dsa_public,
        os_dsa_priv,
        os_dsa_public,
    ) = generate_dsa_keypair_and_certificate()
    dsa_bytes = dsa_cert.public_bytes(serialization.Encoding.DER)
    dsa_priv_bytes = dsa_priv.private_bytes(
        serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dump("python_dsa.dmp")

    (
        ecc_cert,
        ecc_priv,
        ecc_public,
        os_ecc_priv,
        os_ecc_public,
    ) = generate_ecc_keypair_and_certificate()
    ecc_bytes = ecc_cert.public_bytes(serialization.Encoding.DER)
    ecc_priv_bytes = ecc_priv.private_bytes(
        serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dump("python_ecc.dmp")

    (
        ed25519_cert,
        ed25519_priv,
        ed25519_public,
    ) = generate_ed25519_keypair_and_certificate()

    ed25519_bytes = ed25519_cert.public_bytes(serialization.Encoding.DER)
    ed25519_priv_bytes = ed25519_priv.private_bytes(
        serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dump("python_ed25519.dmp")

    ed448_priv, ed448_cert = generate_ed448_keypair_and_certificate()
    ed448_bytes = ed448_cert.public_bytes(serialization.Encoding.DER)
    ed448_priv_bytes = ed448_priv.private_bytes(
        serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dump("python_ed448.dmp")

    dump("python_x509.dmp")

    print(Rule("RSA"))
    print("RSA Public", len(rsa_bytes), hexlify(rsa_bytes))
    print("RSA Private", len(rsa_priv_bytes), hexlify(rsa_priv_bytes))

    print(Rule("DSA"))
    print("DSA", len(dsa_bytes), hexlify(dsa_bytes))
    print("DSA Private", len(dsa_priv_bytes), hexlify(dsa_priv_bytes))

    print(Rule("ECC"))
    print("ECC", len(ecc_bytes), hexlify(ecc_bytes))
    print("ECC Private", len(ecc_priv_bytes), hexlify(ecc_priv_bytes))

    print(Rule("ED25519"))
    print("ED25519", hexlify(ed25519_bytes))
    print(
        "ED25519 Private",
        len(ed25519_priv_bytes),
        hexlify(ed25519_priv_bytes),
        int(hexlify(ed25519_priv_bytes)[32:], 16),
    )

    print(Rule("ED448"))
    print("ED448", hexlify(ed448_bytes))
    print("ED448 Private", len(ed448_priv_bytes), hexlify(ed448_priv_bytes))

    table = Table("Type", "Thumbprint", "Public Integers")
    table.add_row(
        "RSA",
        get_thumbprint(rsa_cert),
        format(rsa_cert.public_key().public_numbers().n, "x")[:40].upper(),
    )
    table.add_row(
        "ECC",
        get_thumbprint(ecc_cert),
        f"X:{str(ecc_cert.public_key().public_numbers().x)[:40]} | Y:{str(ecc_cert.public_key().public_numbers().y)[:40]} ",
    )
    table.add_row(
        "DSA",
        get_thumbprint(dsa_cert),
        format(dsa_cert.public_key().public_numbers().y, "x").upper(),
    )
    table.add_row("ED25519", get_thumbprint(ed25519_cert), "")
    table.add_row("ED448", get_thumbprint(ed448_cert), "")
    print(table)

    # dsa_summary(dsa_priv)
    # ecc_summary(ecc_public, ecc_priv)

    input(f"PID: {os.getpid()} -- Press Enter to continue...")
