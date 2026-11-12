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
        hmac_helper = re.search(
            r"static EVP_MAC_CTX \* openssl_hmac_ctx_new\(.*?\n\}\n",
            source,
            flags=re.S,
        )
        if not hmac_helper:
            failures.append(component + ": provider-backed EVP_MAC HMAC helper missing")
        else:
            for token in (
                'EVP_MAC_fetch(NULL, "HMAC", "provider=default")',
                "EVP_MAC_CTX_new", "EVP_MD_get0_name", "OSSL_MAC_PARAM_DIGEST",
                "EVP_MAC_init", "EVP_MAC_CTX_free",
            ):
                if token not in hmac_helper.group(0):
                    failures.append(component + ": EVP_MAC HMAC helper invariant missing: " + token)
        if "#include <openssl/core_names.h>" not in source or "#include <openssl/params.h>" not in source:
            failures.append(component + ": OpenSSL core_names/params headers missing")
        if "struct crypto_hash" not in source:
            failures.append(component + ": crypto_hash context missing")
        else:
            active_crypto_region = source[source.index("struct crypto_hash"):]
            context = re.search(r"struct crypto_hash\s*\{(.*?)\};", source, flags=re.S)
            if not context or "int failed;" not in context.group(1):
                failures.append(component + ": HMAC context does not retain update failure state")
            update_body = re.search(r"void crypto_hash_update\(.*?\n\}", source, flags=re.S)
            if not update_body or "EVP_MAC_update(ctx->ctx, data, len) != 1" not in update_body.group(0) or "ctx->failed = 1" not in update_body.group(0):
                failures.append(component + ": HMAC update failure is not retained for finish")
            finish_body = re.search(r"int crypto_hash_finish\(.*?\n\}", source, flags=re.S)
            if not finish_body:
                failures.append(component + ": crypto_hash_finish implementation missing")
            else:
                for token in ("if (ctx->failed)", "EVP_MAC_CTX_get_mac_size(ctx->ctx)",
                              "if (*len < required)", "*len = required",
                              "EVP_MAC_final(ctx->ctx, mac, &mdlen, *len)",
                              "return -2;"):
                    if token not in finish_body.group(0):
                        failures.append(component + ": HMAC finish contract invariant missing: " + token)
            vector_body = re.search(r"static int openssl_hmac_vector\(.*?\n\}", source, flags=re.S)
            if not vector_body or "EVP_MAC_update(ctx, addr[i], len[i]) != 1" not in vector_body.group(0):
                failures.append(component + ": HMAC vector update failure is not checked")
            for api in ("HMAC_CTX_new", "HMAC_CTX_free", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final"):
                if re.search(r"\b" + api + r"\s*\(", active_crypto_region):
                    failures.append(component + ": deprecated HMAC call remains in target crypto path: " + api)
            if "EVP_MAC_CTX *ctx;" not in active_crypto_region or "EVP_MAC_CTX_get_mac_size" not in active_crypto_region:
                failures.append(component + ": crypto_hash context/final output-size semantics not migrated")
            if "EVP_MAC_update" not in active_crypto_region or "EVP_MAC_final" not in active_crypto_region:
                failures.append(component + ": HMAC update/final lifecycle not migrated")
    if len(helpers) == 2 and helpers["wappd"] != helpers["1905daemon"]:
        failures.append("WAPP and 1905daemon AES-WRAP helpers diverge")

    hmac_helpers = {}
    for component, source in backends.items():
        match = re.search(r"static EVP_MAC_CTX \* openssl_hmac_ctx_new\(.*?\n\}\n", source, flags=re.S)
        if match:
            hmac_helpers[component] = match.group(0)
    if len(hmac_helpers) == 2 and hmac_helpers["wappd"] != hmac_helpers["1905daemon"]:
        failures.append("WAPP and 1905daemon EVP_MAC HMAC helpers diverge")

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


    dh5_contracts = {}
    for component, source in backends.items():
        helper = re.search(
            r"static EVP_PKEY \* dh5_fromdata\(.*?\n\}\n",
            source,
            flags=re.S,
        )
        generator = re.search(
            r"static EVP_PKEY \* dh5_generate_key\(.*?\n\}\n",
            source,
            flags=re.S,
        )
        if not helper or not generator:
            failures.append(component + ": provider-backed DH5 import/generation helpers missing")
            continue
        helper_text = helper.group(0)
        generator_text = generator.group(0)
        expected_type = '"DHX"' if component == "wappd" else '"DH"'
        for token in (
            "EVP_PKEY_CTX_new_from_name(NULL, " + expected_type + ", NULL)",
            "OSSL_PARAM_BLD_push_BN", "OSSL_PKEY_PARAM_FFC_P",
            "OSSL_PKEY_PARAM_FFC_G", "EVP_PKEY_fromdata_init",
            "EVP_PKEY_fromdata(ctx, &pkey, selection, params)",
            "OSSL_PARAM_BLD_free", "EVP_PKEY_CTX_free",
        ):
            if token not in helper_text:
                failures.append(component + ": DH5 EVP_PKEY fromdata invariant missing: " + token)
        if component == "wappd":
            if "get_group5_order()" not in helper_text or "OSSL_PKEY_PARAM_FFC_Q" not in helper_text:
                failures.append("WAPP DHX migration lost the existing RFC3526 group-5 q parameter")
        elif "OSSL_PKEY_PARAM_FFC_Q" in helper_text:
            failures.append("1905daemon DH migration unexpectedly adds a q parameter absent from its original DH object")
        for token in (
            "EVP_PKEY_KEY_PARAMETERS", "EVP_PKEY_CTX_new_from_pkey",
            "EVP_PKEY_keygen_init", "EVP_PKEY_generate",
        ):
            if token not in generator_text:
                failures.append(component + ": DH5 EVP_PKEY generation invariant missing: " + token)
        init_body = re.search(r"void \* dh5_init\(.*?\n\}", source, flags=re.S)
        fixed_body = re.search(r"void \* dh5_init_fixed\(.*?\n\}", source, flags=re.S)
        derive_body = re.search(r"struct wpabuf \* dh5_derive_shared\(.*?\n\}", source, flags=re.S)
        free_body = re.search(r"void dh5_free\(.*?\n\}", source, flags=re.S)
        if not all((init_body, fixed_body, derive_body, free_body)):
            failures.append(component + ": one or more DH5 production lifecycle functions are missing")
            continue
        init_text, fixed_text = init_body.group(0), fixed_body.group(0)
        derive_text, free_text = derive_body.group(0), free_body.group(0)
        for token in ("EVP_PKEY_get_bn_param", "BN_clear_free(priv_bn)", "wpabuf_clear_free(privkey)"):
            if token not in init_text:
                failures.append(component + ": DH5 generated-key export/cleanup invariant missing: " + token)
        for token in ("INT_MAX", "EVP_PKEY_KEYPAIR", "BN_clear_free(priv_bn)"):
            if token not in fixed_text:
                failures.append(component + ": DH5 fixed-key import/bounds invariant missing: " + token)
        for token in (
            "EVP_PKEY_derive_init", "EVP_PKEY_derive_set_peer",
            "OSSL_EXCHANGE_PARAM_PAD", "unsigned int pad = 0",
            "EVP_PKEY_derive(dctx, NULL, &keylen)",
            "EVP_PKEY_derive(dctx, wpabuf_mhead(res), &keylen)",
            "EVP_PKEY_free(peer)", "EVP_PKEY_CTX_free(dctx)",
        ):
            if token not in derive_text:
                failures.append(component + ": DH5 EVP derive/variable-length output invariant missing: " + token)
        if "EVP_PKEY_free((EVP_PKEY *) ctx)" not in free_text:
            failures.append(component + ": DH5 context ownership is not released with EVP_PKEY_free")
        dh5_contracts[component] = helper_text
    if set(dh5_contracts) != {"wappd", "1905daemon"}:
        failures.append("Both WAPP DHX and 1905daemon DH provider paths must be present")

result = {
    "schema_version": 1,
    "scope": "n60-easymesh-openssl-3.5.9",
    "batch": ["AES_set_decrypt_key", "AES_set_encrypt_key", "AES_unwrap_key",
              "AES_wrap_key", "DES_set_key", "DES_ecb_encrypt", "HMAC_CTX_new",
              "HMAC_CTX_free", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final", "DH_new",
              "DH_generate_key", "DH_set0_pqg", "DH_set0_key", "DH_get0_key",
              "DH_size", "DH_compute_key", "DH_free"],
    "source_root": str(root),
    "result": "PASS" if not failures else "FAIL",
    "failures": failures,
}
print(json.dumps(result, indent=2))
if failures:
    raise SystemExit(1)
