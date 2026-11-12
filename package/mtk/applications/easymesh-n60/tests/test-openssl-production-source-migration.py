#!/usr/bin/env python3
"""Fail-closed source contract for the first N60 EasyMesh OpenSSL API migration batch."""
import argparse
import json
import re
import subprocess
import tempfile
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
    "wapp_dpp_source": root / "wappd/dpp/dpp.c",
    "p1905_dpp_source": root / "1905daemon/src/dpp.c",
}
for name, path in paths.items():
    if not path.is_file():
        failures.append(f"missing {name}: {path}")

if not failures:
    backends = {
        "wappd": paths["wapp_backend"].read_text(encoding="utf-8"),
        "1905daemon": paths["p1905_backend"].read_text(encoding="utf-8"),
    }
    # Patch 029 is applied after 028 in the same locked Native Prepare series.
    # Check the actual DPP production comparison in both vendor backends.
    for component, dpp_path in (
        ("WAPP", paths["wapp_dpp_source"]),
        ("1905daemon", paths["p1905_dpp_source"]),
    ):
        dpp_source = dpp_path.read_text(encoding="utf-8")
        eq_call = "EVP_PKEY_eq(key, auth->own_protocol_key)"
        cmp_call = "EVP_PKEY_cmp(key, auth->own_protocol_key)"
        if dpp_source.count(eq_call) != 1 or dpp_source.count(cmp_call) != 1:
            failures.append(component + ": patch 029 must retain exactly one EVP_PKEY_eq and one legacy EVP_PKEY_cmp call")
        eq_pos = dpp_source.find(eq_call)
        cmp_pos = dpp_source.find(cmp_call)
        guard_pos = dpp_source.rfind("#if OPENSSL_VERSION_NUMBER >= 0x30000000L", 0, eq_pos)
        else_pos = dpp_source.find("#else", eq_pos, cmp_pos)
        endif_pos = dpp_source.find("#endif", cmp_pos)
        if min(eq_pos, cmp_pos, guard_pos, else_pos, endif_pos) < 0 or not (guard_pos < eq_pos < else_pos < cmp_pos < endif_pos):
            failures.append(component + ": patch 029 OpenSSL 3 EVP_PKEY_eq / legacy EVP_PKEY_cmp conditional is missing")

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


    # Compile and execute the exact DH5 production helpers/functions extracted
    # from Native Prepare output. Only the wpabuf adapter is test scaffolding.
    if set(dh5_contracts) == {"wappd", "1905daemon"}:
        for component, source in backends.items():
            extract_patterns = [
                (r"static BIGNUM \* get_group5_prime\(void\)\n\{.*?\n\}", "get_group5_prime"),
                (r"static EVP_PKEY \* dh5_fromdata\(.*?\n\}\n", "dh5_fromdata"),
                (r"static EVP_PKEY \* dh5_generate_key\(.*?\n\}\n", "dh5_generate_key"),
                (r"void \* dh5_init\(.*?\n\}", "dh5_init"),
                (r"void \* dh5_init_fixed\(.*?\n\}", "dh5_init_fixed"),
                (r"struct wpabuf \* dh5_derive_shared\(.*?\n\}", "dh5_derive_shared"),
                (r"void dh5_free\(.*?\n\}", "dh5_free"),
            ]
            extracted = {}
            for pattern, name in extract_patterns:
                match = re.search(pattern, source, flags=re.S)
                if not match:
                    failures.append(component + ": cannot extract production " + name + " for runtime regression")
                else:
                    extracted[name] = match.group(0)
            if component == "wappd":
                match = re.search(
                    r"static BIGNUM \* get_group5_order\(void\)\n\{.*?\n\}",
                    source,
                    flags=re.S,
                )
                if not match:
                    failures.append("WAPP: cannot extract production get_group5_order for DHX regression")
                else:
                    extracted["get_group5_order"] = match.group(0)
            if len(extracted) != (8 if component == "wappd" else 7):
                continue

            prefix = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error OpenSSL 3 or newer is required
#endif
typedef unsigned char u8;
struct wpabuf { size_t len, size; u8 *buf; };
static struct wpabuf *wpabuf_alloc(size_t n)
{
    struct wpabuf *b = OPENSSL_zalloc(sizeof(*b));
    if (!b) return NULL;
    b->size = n;
    b->buf = OPENSSL_malloc(n ? n : 1);
    if (!b->buf) { OPENSSL_free(b); return NULL; }
    return b;
}
static void wpabuf_free(struct wpabuf *b)
{
    if (b) { OPENSSL_free(b->buf); OPENSSL_free(b); }
}
static void wpabuf_clear_free(struct wpabuf *b)
{
    if (b) { OPENSSL_clear_free(b->buf, b->size); OPENSSL_clear_free(b, sizeof(*b)); }
}
static size_t wpabuf_len(const struct wpabuf *b) { return b ? b->len : 0; }
static const u8 *wpabuf_head(const struct wpabuf *b) { return b ? b->buf : NULL; }
static u8 *wpabuf_mhead(struct wpabuf *b) { return b ? b->buf : NULL; }
static u8 *wpabuf_put(struct wpabuf *b, size_t n)
{
    u8 *p;
    if (!b || n > b->size - b->len) return NULL;
    p = b->buf + b->len;
    b->len += n;
    return p;
}
"""
            suffix = r"""
static int same_secret(const struct wpabuf *a, const struct wpabuf *b)
{
    return a && b && a->len == b->len && !memcmp(a->buf, b->buf, a->len);
}
int main(void)
{
    struct wpabuf *apriv = NULL, *apub = NULL, *bpriv = NULL, *bpub = NULL;
    struct wpabuf *sa = NULL, *sb = NULL, *sf = NULL;
    struct wpabuf *small_priv = NULL, *small_pub = NULL, *peer_pub = NULL;
    struct wpabuf *short_secret = NULL;
    void *a = NULL, *b = NULL, *fixed = NULL, *small = NULL;
    int ret = 1;

    a = dh5_init(&apriv, &apub);
    b = dh5_init(&bpriv, &bpub);
    if (!a || !b || !apriv || !apub || !bpriv || !bpub) goto done;
    sa = dh5_derive_shared(a, bpub, apriv);
    sb = dh5_derive_shared(b, apub, bpriv);
    if (!same_secret(sa, sb)) goto done;

    fixed = dh5_init_fixed(apriv, apub);
    if (!fixed) goto done;
    sf = dh5_derive_shared(fixed, bpub, apriv);
    if (!same_secret(sa, sf)) goto done;

    small_priv = wpabuf_alloc(1);
    small_pub = wpabuf_alloc(1);
    peer_pub = wpabuf_alloc(1);
    if (!small_priv || !small_pub || !peer_pub) goto done;
    *wpabuf_put(small_priv, 1) = 2;
    *wpabuf_put(small_pub, 1) = 4;
    *wpabuf_put(peer_pub, 1) = 8;
    small = dh5_init_fixed(small_priv, small_pub);
    if (!small) goto done;
    short_secret = dh5_derive_shared(small, peer_pub, small_priv);
    if (!short_secret || short_secret->len != 1 || short_secret->buf[0] != 64)
        goto done;

    printf("PASS %s generated/imported keys, reciprocal agreement and unpadded short secret\n",
           EVP_PKEY_is_a((EVP_PKEY *) a, "DHX") ? "DHX" : "DH");
    ret = 0;
done:
    if (ret) ERR_print_errors_fp(stderr);
    dh5_free(a);
    dh5_free(b);
    dh5_free(fixed);
    dh5_free(small);
    wpabuf_clear_free(apriv);
    wpabuf_clear_free(apub);
    wpabuf_clear_free(bpriv);
    wpabuf_clear_free(bpub);
    wpabuf_clear_free(sa);
    wpabuf_clear_free(sb);
    wpabuf_clear_free(sf);
    wpabuf_clear_free(small_priv);
    wpabuf_clear_free(small_pub);
    wpabuf_clear_free(peer_pub);
    wpabuf_clear_free(short_secret);
    return ret;
}
"""
            ordered_names = ["get_group5_prime"]
            if component == "wappd":
                ordered_names.append("get_group5_order")
            ordered_names.extend([
                "dh5_fromdata", "dh5_generate_key", "dh5_init",
                "dh5_init_fixed", "dh5_derive_shared", "dh5_free",
            ])
            c_source = prefix + "\n".join(extracted[name] for name in ordered_names) + suffix
            try:
                with tempfile.TemporaryDirectory(prefix="n60-dh5-regression-") as temp_dir:
                    executable = Path(temp_dir) / "dh5-production-regression"
                    compile_result = subprocess.run(
                        [
                            "cc", "-DOPENSSL_NO_DEPRECATED",
                            "-DOPENSSL_API_COMPAT=0x30000000L",
                            "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter", "-x", "c", "-",
                            "-o", str(executable), "-lcrypto",
                        ],
                        input=c_source,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    if compile_result.returncode:
                        failures.append(
                            component + ": extracted production DH5 compile failed: "
                            + compile_result.stderr[-2000:]
                        )
                        continue
                    runtime_result = subprocess.run(
                        [str(executable)], text=True, capture_output=True, check=False
                    )
                    if runtime_result.returncode:
                        failures.append(
                            component + ": extracted production DH5 runtime regression failed: "
                            + runtime_result.stdout[-1000:] + runtime_result.stderr[-2000:]
                        )
            except OSError as exc:
                failures.append(component + ": cannot run extracted production DH5 regression: " + str(exc))

result = {
    "schema_version": 1,
    "scope": "n60-easymesh-openssl-3.5.9",
    "batch": ["AES_set_decrypt_key", "AES_set_encrypt_key", "AES_unwrap_key",
              "AES_wrap_key", "DES_set_key", "DES_ecb_encrypt", "HMAC_CTX_new",
              "HMAC_CTX_free", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final", "DH_new",
              "DH_generate_key", "DH_set0_pqg", "DH_set0_key", "DH_get0_key",
              "DH_size", "DH_compute_key", "DH_free", "EVP_PKEY_cmp"],
    "source_root": str(root),
    "result": "PASS" if not failures else "FAIL",
    "failures": failures,
}
print(json.dumps(result, indent=2))
if failures:
    raise SystemExit(1)
