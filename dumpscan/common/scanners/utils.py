from binascii import hexlify

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate


def format_thumbprint(cert: Certificate):
    return hexlify(cert.fingerprint(hashes.SHA1())).decode().upper()
