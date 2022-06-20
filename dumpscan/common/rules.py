YARA_RULES = {
    # Locate x509 structures based on ASN.1
    "x509": {
        "x509": "rule x509 {strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a}",
        "pkcs": "rule pkcs {strings: $a = {30 82 ?? ?? 02 01 00} condition: $a}",
    },
    # Locate RSA structs following "MSRK" magic header
    "symcrypt": {
        "rsa": "rule rsa {strings: $a = {28 00 00 00 4b 52 53 4d ?? ?? ?? ??} condition: $a}",
    },
}
