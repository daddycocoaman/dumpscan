yara_template = "rule {0} {{ strings: $ = {1} condition: any of them}}"

YARA_RULES = {
    # Locate x509 structures based on ASN.1
    "x509": {
        "x509": yara_template.format("x509", "{30 (81|82) (??|?? ??) 30 (81|82)}"),
        "pkcs": yara_template.format("pkcs", "{30 (??|?? ??|?? ?? ??) 02 01 00}"),
    },
    "symcrypt": {
        # Locate RSA structs following "MSRK" magic header
        "rsa": yara_template.format("rsa", "{28 00 00 00 4b 52 53 4d}"),
        # Locate DSA structs following "MSKY" magic header
        "dsa": yara_template.format("dsa", "{30 00 00 00 59 4b 53 4d}"),
        # Locate ECC structs following "MSKY" magic header
        "ecc": yara_template.format("ecc", "{28 00 00 00 59 4b 53 4d}"),
    },
}
