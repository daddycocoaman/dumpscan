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
    # https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    "bcrypt": {
        "rsa_public": yara_template.format("rsa_public", '"RSA1"'),
        "rsa_private": yara_template.format("rsa_private", '"RSA2"'),
        "rsa_fullprivate": yara_template.format("rsa_fullprivate", '"RSA3"'),
        "dsa_public_v2": yara_template.format("dsa_public_v2", '"DPB2"'),
        "dsa_private_v2": yara_template.format("dsa_private_v2", '"DPV2"'),
        "ecdh_public_256": yara_template.format("ecdh_public_256", '"ECK1"'),
        "ecdh_private_256": yara_template.format("ecdh_private_256", '"ECK2"'),
        "ecdh_public_384": yara_template.format("ecdh_public_384", '"ECK3"'),
        "ecdh_private_384": yara_template.format("ecdh_private_384", '"ECK4"'),
        "ecdh_public_521": yara_template.format("ecdh_public_521", '"ECK5"'),
        "ecdh_private_521": yara_template.format("ecdh_private_521", '"ECK6"'),
        "ecdsa_public_256": yara_template.format("ecdsa_public_256", '"ECS1"'),
        "ecdsa_private_256": yara_template.format("ecdsa_private_256", '"ECS2"'),
        "ecdsa_public_384": yara_template.format("ecdsa_public_384", '"ECS3"'),
        "ecdsa_private_384": yara_template.format("ecdsa_private_384", '"ECS4"'),
        "ecdsa_public_521": yara_template.format("ecdsa_public_521", '"ECS5"'),
        "ecdsa_private_521": yara_template.format("ecdsa_private_521", '"ECS6"'),
    },
}
