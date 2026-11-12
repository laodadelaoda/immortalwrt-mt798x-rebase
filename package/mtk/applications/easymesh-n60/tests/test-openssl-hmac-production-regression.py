#!/usr/bin/env python3
"""Compile the exact prepared WAPP and 1905daemon HMAC implementations into a host regression harness."""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def extract_c_block(source: str, pattern: str, label: str) -> str:
    match = re.search(pattern, source, re.MULTILINE)
    if not match:
        raise ValueError(f"{label}: definition not found")
    start = match.start()
    brace = source.find("{", match.start())
    if brace < 0:
        raise ValueError(f"{label}: opening brace not found")
    depth = 0
    state = "code"
    escaped = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in {"string", "char"}:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        else:
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                i += 1
            elif ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        i += 1
    raise ValueError(f"{label}: unterminated definition")


def production_fragments(source_path: Path, header_path: Path) -> str:
    source = source_path.read_text(encoding="utf-8", errors="replace")
    header = header_path.read_text(encoding="utf-8", errors="replace")
    definitions = [
        extract_c_block(header, r"\benum\s+crypto_hash_alg\s*\{", "crypto_hash_alg enum") + ";",
        extract_c_block(source, r"(?m)^[ \t]*static[ \t]+EVP_MAC_CTX[ \t]*\*[ \t]*openssl_hmac_ctx_new[ \t]*\(", "openssl_hmac_ctx_new"),
        extract_c_block(source, r"(?m)^[ \t]*struct[ \t]+crypto_hash[ \t]*\{", "struct crypto_hash") + ";",
        extract_c_block(source, r"(?m)^[ \t]*struct[ \t]+crypto_hash[ \t]*\*[ \t]*crypto_hash_init[ \t]*\(", "crypto_hash_init"),
        extract_c_block(source, r"(?m)^[ \t]*void[ \t]+crypto_hash_update[ \t]*\(", "crypto_hash_update"),
        extract_c_block(source, r"(?m)^[ \t]*int[ \t]+crypto_hash_finish[ \t]*\(", "crypto_hash_finish"),
        extract_c_block(source, r"(?m)^[ \t]*static[ \t]+int[ \t]+openssl_hmac_vector[ \t]*\(", "openssl_hmac_vector"),
    ]
    return "\n\n".join(definitions)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--openssl-include", type=Path, required=True)
    p.add_argument("--openssl-lib-dir", type=Path, required=True)
    p.add_argument("--test-harness", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--compiler", default=os.environ.get("CC", "cc"))
    a = p.parse_args()
    root = a.source_root.resolve()
    out = a.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    harness = a.test_harness.read_text(encoding="utf-8")
    # The harness is test logic only. Production definitions are extracted from
    # the exact native-Prepare source tree below; duplicating them here would
    # compile a parallel implementation instead of testing production code.
    production_symbols = (
        "openssl_hmac_ctx_new", "openssl_hmac_vector", "crypto_hash_init",
        "crypto_hash_update", "crypto_hash_finish",
    )
    for symbol in production_symbols:
        declaration = rf"(?m)^\s*(?:static\s+)?(?:[\w]+\s+)+\*?\s*{re.escape(symbol)}\s*\("
        if re.search(declaration, harness):
            raise ValueError(f"test harness must not redefine prepared production symbol: {symbol}")
    if re.search(r"(?m)^\s*(?:enum\s+crypto_hash_alg|struct\s+crypto_hash)\s*\{", harness):
        raise ValueError("test harness must not redefine production HMAC types")
    preamble = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
typedef unsigned char u8;
#define CONFIG_SHA256 1
#define TEST_FAIL() 0
static int test_fail_next_mac_update;
static int testable_EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
    if (test_fail_next_mac_update) {
        test_fail_next_mac_update = 0;
        return 0;
    }
    return EVP_MAC_update(ctx, data, len);
}
#define EVP_MAC_update testable_EVP_MAC_update
static void *os_zalloc(size_t size) { return calloc(1, size); }
static void bin_clear_free(void *ptr, size_t size)
{
    if (ptr) { OPENSSL_cleanse(ptr, size); free(ptr); }
}
'''
    cases = [
        ("wappd", root / "wappd/crypto/crypto_openssl.c", root / "wappd/crypto/crypto.h"),
        ("1905daemon", root / "1905daemon/src/crypto_openssl.c", root / "1905daemon/src/crypto/crypto.h"),
    ]
    run_env = os.environ.copy()
    run_env["LD_LIBRARY_PATH"] = str(a.openssl_lib_dir.resolve()) + os.pathsep + run_env.get("LD_LIBRARY_PATH", "")
    run_env["OPENSSL_MODULES"] = str(a.openssl_lib_dir.resolve() / "providers")
    run_env["OPENSSL_CONF"] = "/dev/null"
    failures = []
    for name, source, header in cases:
        try:
            if not source.is_file() or not header.is_file():
                raise FileNotFoundError(
                    f"prepared {name} HMAC source/header missing: {source} / {header}"
                )
            generated = out / f"{name}-hmac-production-regression.c"
            generated.write_text(
                preamble + "\n" + production_fragments(source, header) + "\n" + harness,
                encoding="utf-8",
            )
            binary = out / f"{name}-hmac-production-regression-test"
            cmd = [
                a.compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-I", str(a.openssl_include.resolve()), str(generated),
                "-L", str(a.openssl_lib_dir.resolve()),
                f"-Wl,-rpath,{a.openssl_lib_dir.resolve()}",
                "-lcrypto", "-ldl", "-pthread", "-lresolv", "-o", str(binary),
            ]
            compile_log = out / f"{name}-hmac-production-compile.log"
            try:
                with compile_log.open("w", encoding="utf-8") as stream:
                    subprocess.run(cmd, check=True, stdout=stream, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                print(f"FAIL: prepared {name} HMAC production harness compilation:", file=sys.stderr)
                print(compile_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr, end="")
                raise
            log = out / f"{name}-hmac-production-regressions.log"
            try:
                with log.open("w", encoding="utf-8") as stream:
                    subprocess.run([str(binary)], check=True, env=run_env, stdout=stream, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                print(f"FAIL: prepared {name} HMAC regression details:", file=sys.stderr)
                print(log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr, end="")
                raise
            print(f"PASS: actual prepared {name} HMAC functions compiled and passed the production regression harness")
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            failures.append(f"{name}: {exc}")
            print(f"FAIL: {name} HMAC backend: {exc}", file=sys.stderr)
            # Continue so the other production backend always gets its own
            # compile/run attempt and independent diagnostic log.
            continue

    if failures:
        print("FAIL: independent HMAC backend results:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS_TEST_ID:hmac_evp_mac_production_digest_key_vector")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"FAIL: {exc}")
