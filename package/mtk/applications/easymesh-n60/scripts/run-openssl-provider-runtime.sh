#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 <openssl-source> <test.c> <evidence-dir> <repo-root>" >&2; exit 2; }
src="$(realpath "$1")"; test_c="$(realpath "$2")"; out="$3"; repo="$(realpath "$4")"
mkdir -p "$out"; exec > >(tee "$out/provider-runtime.log") 2>&1
[[ -s "$src/Configure" && -s "$src/include/openssl/opensslv.h" && -s "$test_c" && -d "$repo" ]] || { echo "FAIL: Provider runtime input missing"; exit 1; }
for item in "OPENSSL_VERSION_MAJOR 3" "OPENSSL_VERSION_MINOR 5" "OPENSSL_VERSION_PATCH 9"; do
 set -- $item
 grep -Eq "^[[:space:]]*#[[:space:]]*define[[:space:]]+$1[[:space:]]+$2([[:space:]]|$)" "$src/include/openssl/opensslv.h" || { echo "FAIL: wrong OpenSSL version: $item"; exit 1; }
done
build="$RUNNER_TEMP/n60-openssl-provider-host-build"; rm -rf "$build"; mkdir -p "$build"; cp -a "$src" "$build/openssl-src"
cd "$build/openssl-src"
perl ./Configure linux-x86_64 no-shared no-tests no-apps no-docs --prefix="$build/install"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" build_libs
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$test_c" "$build/openssl-src/libcrypto.a" -ldl -pthread -o "$out/provider-runtime-test"
OPENSSL_CONF=/dev/null "$out/provider-runtime-test"
sha256sum "$test_c" "$out/provider-runtime-test" > "$out/SHA256SUMS"
printf '{"openssl_version":"3.5.9","provider":"default","result":"PASS"}\n' > "$out/provider-runtime-result.json"
