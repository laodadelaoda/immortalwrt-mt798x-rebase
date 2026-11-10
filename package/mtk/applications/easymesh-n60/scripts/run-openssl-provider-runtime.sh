#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 <openssl-source> <test.c> <evidence-dir> <repo-root>" >&2; exit 2; }
src="$(realpath "$1")"; test_c="$(realpath "$2")"; out="$3"; repo="$(realpath "$4")"
mkdir -p "$out"; exec > >(tee "$out/provider-runtime.log") 2>&1
[[ -s "$src/Configure" && -s "$src/include/openssl/opensslv.h.in" && -s "$test_c" && -d "$repo" ]] || { echo "FAIL: Provider runtime input missing (expected OpenSSL Configure and opensslv.h.in template)"; exit 1; }
PKG_VERSION="$(sed -n 's/^PKG_VERSION:=//p' "$repo/package/libs/openssl/Makefile" | head -n 1)"
[[ "$PKG_VERSION" == "3.5.9" ]] || { echo "FAIL: repository OpenSSL package is not pinned to 3.5.9 (found: $PKG_VERSION)"; exit 1; }
echo "PASS: OpenSSL source template is present and package Makefile pins the audited archive to 3.5.9."
build="$RUNNER_TEMP/n60-openssl-provider-host-build"; rm -rf "$build"; mkdir -p "$build"; cp -a "$src" "$build/openssl-src"
cd "$build/openssl-src"
perl ./Configure linux-x86_64 no-shared no-tests no-apps no-docs --prefix="$build/install"
# OpenSSL 3.5.9 Configure generates configuration.h immediately, but public
# headers (including opensslv.h) are rendered by the generated Makefile.
# Build the native libraries first so the header-generation prerequisites run.
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" build_libs
test -s include/openssl/opensslv.h || { echo "FAIL: build_libs did not generate include/openssl/opensslv.h"; exit 1; }
for item in "OPENSSL_VERSION_MAJOR 3" "OPENSSL_VERSION_MINOR 5" "OPENSSL_VERSION_PATCH 9"; do
 set -- $item
 grep -Eq "^[[:space:]]*#[[:space:]]*define[[:space:]]+$1[[:space:]]+$2([[:space:]]|$)" include/openssl/opensslv.h || { echo "FAIL: generated OpenSSL header version mismatch: $item"; exit 1; }
done
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$test_c" "$build/openssl-src/libssl.a" "$build/openssl-src/libcrypto.a" -ldl -pthread -lresolv -o "$out/provider-runtime-test"
OPENSSL_CONF=/dev/null "$out/provider-runtime-test"
sha256sum "$test_c" "$out/provider-runtime-test" > "$out/SHA256SUMS"
printf '{"openssl_version":"3.5.9","provider":"default","result":"PASS"}\n' > "$out/provider-runtime-result.json"
