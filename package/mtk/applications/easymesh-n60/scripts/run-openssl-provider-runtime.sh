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
perl ./Configure linux-x86_64 shared no-tests no-apps no-docs --prefix="$build/install"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
test -s include/openssl/opensslv.h || { echo "FAIL: OpenSSL build did not generate include/openssl/opensslv.h"; exit 1; }
test -s providers/legacy.so || { echo "FAIL: OpenSSL 3.5.9 Legacy Provider module was not built; DES migration regression cannot be validated."; exit 1; }
for item in "OPENSSL_VERSION_MAJOR 3" "OPENSSL_VERSION_MINOR 5" "OPENSSL_VERSION_PATCH 9"; do
 set -- $item
 grep -Eq "^[[:space:]]*#[[:space:]]*define[[:space:]]+$1[[:space:]]+$2([[:space:]]|$)" include/openssl/opensslv.h || { echo "FAIL: generated OpenSSL header version mismatch: $item"; exit 1; }
done
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$test_c" -L"$build/openssl-src" -Wl,-rpath,"$build/openssl-src" -lssl -lcrypto -ldl -pthread -lresolv -o "$out/provider-runtime-test"
LD_LIBRARY_PATH="$build/openssl-src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" OPENSSL_MODULES="$build/openssl-src/providers" OPENSSL_CONF=/dev/null "$out/provider-runtime-test"
REGRESSION_C="$repo/package/mtk/applications/easymesh-n60/tests/test-openssl-api-migration-regressions.c"
REGRESSION_MATRIX="$repo/package/mtk/applications/easymesh-n60/tests/openssl-40-api-regression-matrix.json"
test -s "$REGRESSION_C" && test -s "$REGRESSION_MATRIX"
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$REGRESSION_C" -L"$build/openssl-src" -Wl,-rpath,"$build/openssl-src" -lcrypto -ldl -pthread -lresolv -o "$out/api-migration-regression-test"
LD_LIBRARY_PATH="$build/openssl-src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" OPENSSL_MODULES="$build/openssl-src/providers" OPENSSL_CONF=/dev/null "$out/api-migration-regression-test" | tee "$out/api-migration-regressions.log"
python3 - "$REGRESSION_MATRIX" "$REGRESSION_C" "$out/api-migration-regressions.log" "$out/openssl-api-regression-results.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
matrix_path,source_path,log_path,out_path=map(Path,sys.argv[1:])
matrix=json.loads(matrix_path.read_text())
passed={line.split("PASS_TEST_ID:",1)[1].strip() for line in log_path.read_text().splitlines() if "PASS_TEST_ID:" in line}
required=set(matrix.get("required_test_ids",[]))
missing=sorted(required-passed)
if missing:
    raise SystemExit("missing API regression test results: "+", ".join(missing))
coverage=[]
for item in matrix.get("api_test_coverage",[]):
    ids=item.get("test_ids",[])
    status="PASS" if ids and all(x in passed for x in ids) else "FAIL"
    coverage.append({"api":item["api"],"test_ids":ids,"status":status})
if len(coverage)!=40 or any(x["status"]!="PASS" for x in coverage):
    raise SystemExit("40-API regression coverage is incomplete")
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
result={"schema_version":1,"scope_id":matrix["scope_id"],"openssl_version":"3.5.9","status":"PASS",
        "api_count":len(coverage),"required_test_ids":sorted(required),
        "passed_test_ids":sorted(passed),"api_coverage":coverage,
        "inputs":{"matrix_sha256":sha(matrix_path),"test_source_sha256":sha(source_path),"test_log_sha256":sha(log_path)}}
out_path.write_text(json.dumps(result,indent=2)+"\n")
print("PASS: all 40 EasyMesh API entries are covered by the provider-native migration regression suite.")
PY
sha256sum "$test_c" "$REGRESSION_C" "$out/provider-runtime-test" "$out/api-migration-regression-test" > "$out/SHA256SUMS"
printf '{"openssl_version":"3.5.9","providers":["default","legacy"],"legacy_provider_scope":"regression-test-only","result":"PASS"}\n' > "$out/provider-runtime-result.json"
