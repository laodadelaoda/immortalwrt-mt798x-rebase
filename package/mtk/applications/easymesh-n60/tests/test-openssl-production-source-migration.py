#!/usr/bin/env python3
"""Fail-closed source contract for the first N60 EasyMesh OpenSSL API migration batch."""
import argparse
import json
import re
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("source_root", type=Path)
a = p.parse_args()
root = a.source_root.resolve()
failures = []

paths = {
    "wapp_backend": root / "wappd/crypto/crypto_openssl.c",
    "p1905_backend": root / "1905daemon/src/crypto_openssl.c",
    "wapp_crypto_header": root / "wappd/crypto/crypto.h",
    "p1905_crypto_header": root / "1905daemon/src/crypto/crypto.h",
    "p1905_des_source": root / "1905daemon/src/crypto/des-internal.c",
    "p1905_crypto_makefile": root / "1905daemon/src/crypto/Makefile",
    "p1905_main_makefile": root / "1905daemon/Makefile",
    "p1905_ms_funcs": root / "1905daemon/src/crypto/ms_funcs.c",
}
for name, path in paths.items():
    if not path.is_file():
        failures.append(f"missing {name}: {path}")

if not failures:
    backends = {
        "wappd": paths["wapp_backend"].read_text(encoding="utf-8"),
        "1905daemon": paths["p1905_backend"].read_text(encoding="utf-8"),
    }
    forbidden = (
        "AES_set_decrypt_key", "AES_set_encrypt_key", "AES_unwrap_key",
        "AES_wrap_key", "DES_set_key", "DES_ecb_encrypt",
    )
    helpers = {}
    for component, source in backends.items():
        for api in forbidden:
            if re.search(r"\b" + re.escape(api) + r"\s*\(", source):
                failures.append(f"{component}: deprecated production call remains: {api}")
        match = re.search(
            r"static int openssl_aes_wrap_crypt\(.*?\n\}\n",
            source,
            flags=re.S,
        )
        if not match:
            failures.append(f"{component}: provider-backed AES-WRAP helper missing")
            continue
        helper = match.group(0)
        helpers[component] = helper
        for token in (
            'EVP_CIPHER_fetch(NULL, cipher_name, "provider=default")',
            "EVP_CIPHER_CTX_FLAG_WRAP_ALLOW",
            "EVP_EncryptInit_ex2", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
            "EVP_DecryptInit_ex2", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
            '"AES-128-WRAP"', '"AES-192-WRAP"', '"AES-256-WRAP"',
            "n < 2", "INT_MAX / 8 - 1", "outl + finl != out_len",
            "OPENSSL_clear_free(tmp, tmp_len)", "OPENSSL_cleanse(out, out_len)",
        ):
            if token not in helper:
                failures.append(f"{component}: AES-WRAP semantic guard missing: {token}")
        if "#include <limits.h>" not in source:
            failures.append(f"{component}: INT_MAX header missing")
    if len(helpers) == 2 and helpers["wappd"] != helpers["1905daemon"]:
        failures.append("WAPP and 1905daemon AES-WRAP helpers diverge")

    wapp_header = paths["wapp_crypto_header"].read_text(encoding="utf-8")
    if re.search(r"^\s*(?:int|long)\s+des_encrypt\s*\(", wapp_header, re.M):
        failures.append("WAPP still declares the unused DES wrapper")

    p1905_header = paths["p1905_crypto_header"].read_text(encoding="utf-8")
    if not re.search(r"^\s*int\s+des_encrypt\s*\(", p1905_header, re.M):
        failures.append("1905daemon DES interface declaration was lost")

    des_source = paths["p1905_des_source"].read_text(encoding="utf-8")
    for token in ("int des_encrypt(", "deskey(pkey, 0, ek);", "desfunc(work, ek);",
                  "os_memset(pkey, 0, sizeof(pkey));", "os_memset(ek, 0, sizeof(ek));"):
        if token not in des_source:
            failures.append("1905daemon internal DES semantic evidence missing: " + token)

    crypto_make = paths["p1905_crypto_makefile"].read_text(encoding="utf-8")
    if "des-internal.o" not in crypto_make:
        failures.append("1905daemon internal DES object is not part of libcrypto.a")

    main_make = paths["p1905_main_makefile"].read_text(encoding="utf-8")
    if "CRYPTO_LIB = src/crypto/libcrypto.a" not in main_make or "$(CRYPTO_LIB)" not in main_make:
        failures.append("1905daemon link recipe no longer includes the internal crypto archive")

    ms_funcs = paths["p1905_ms_funcs"].read_text(encoding="utf-8")
    des_uses = len(re.findall(r"\bdes_encrypt\s*\(", ms_funcs))
    if des_uses != 5:
        failures.append(f"1905daemon MSCHAPv2 internal DES call-site count changed: {des_uses}, expected 5")

result = {
    "schema_version": 1,
    "scope": "n60-easymesh-openssl-3.5.9",
    "batch": ["AES_set_decrypt_key", "AES_set_encrypt_key", "AES_unwrap_key",
              "AES_wrap_key", "DES_set_key", "DES_ecb_encrypt"],
    "source_root": str(root),
    "result": "PASS" if not failures else "FAIL",
    "failures": failures,
}
print(json.dumps(result, indent=2))
if failures:
    raise SystemExit(1)
