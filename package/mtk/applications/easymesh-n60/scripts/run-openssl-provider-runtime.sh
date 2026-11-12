#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 <openssl-source> <test.c> <evidence-dir> <repo-root>" >&2; exit 2; }
src="$(realpath "$1")"; test_c="$(realpath "$2")"; out="$3"; repo="$(realpath "$4")"
mkdir -p "$out"; exec > >(tee "$out/provider-runtime.log") 2>&1
stage="input-validation"
write_failure_evidence() {
    local rc=$?
    if [[ "$rc" -eq 0 ]]; then return 0; fi
    set +e
    python3 - "$out" "$stage" "$rc" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
failure = {"stage": sys.argv[2], "exit_code": int(sys.argv[3])}
regression = root / "openssl-api-regression-results.json"
try:
    data = json.loads(regression.read_text(encoding="utf-8")) if regression.is_file() else {
        "schema_version": 1, "scope_id": "n60-easymesh-openssl-3.5.9",
        "openssl_version": "3.5.9", "api_count": 0,
        "required_test_ids": [], "passed_test_ids": [], "api_coverage": [],
        "inputs": {}
    }
except Exception as exc:
    data = {"schema_version": 1, "scope_id": "n60-easymesh-openssl-3.5.9",
            "openssl_version": "3.5.9", "api_count": 0,
            "required_test_ids": [], "passed_test_ids": [], "api_coverage": [],
            "inputs": {}, "evidence_parse_error": str(exc)}
data["status"] = "FAIL"
data["failure"] = failure
regression.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
provider = root / "provider-runtime-result.json"
try:
    result = json.loads(provider.read_text(encoding="utf-8")) if provider.is_file() else {
        "schema_version": 1, "openssl_version": "3.5.9",
        "providers": [], "legacy_provider_scope": "regression-test-only"
    }
except Exception as exc:
    result = {"schema_version": 1, "openssl_version": "3.5.9",
              "providers": [], "legacy_provider_scope": "regression-test-only",
              "evidence_parse_error": str(exc)}
result["result"] = "FAIL"
result["failure"] = failure
provider.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
PY
}
trap write_failure_evidence EXIT

[[ -s "$src/Configure" && -s "$src/include/openssl/opensslv.h.in" && -s "$test_c" && -d "$repo" ]] || { echo "FAIL: Provider runtime input missing (expected OpenSSL Configure and opensslv.h.in template)"; exit 1; }
stage="source-validation"
PKG_VERSION="$(sed -n 's/^PKG_VERSION:=//p' "$repo/package/libs/openssl/Makefile" | head -n 1)"
[[ "$PKG_VERSION" == "3.5.9" ]] || { echo "FAIL: repository OpenSSL package is not pinned to 3.5.9 (found: $PKG_VERSION)"; exit 1; }
echo "PASS: OpenSSL source template is present and package Makefile pins the audited archive to 3.5.9."
build="$RUNNER_TEMP/n60-openssl-provider-host-build"; rm -rf "$build"; mkdir -p "$build"; cp -a "$src" "$build/openssl-src"
cd "$build/openssl-src"
stage="openssl-host-build"
perl ./Configure linux-x86_64 shared no-tests no-apps no-docs --prefix="$build/install"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
test -s include/openssl/opensslv.h || { echo "FAIL: OpenSSL build did not generate include/openssl/opensslv.h"; exit 1; }
test -s providers/legacy.so || { echo "FAIL: OpenSSL 3.5.9 Legacy Provider module was not built; DES migration regression cannot be validated."; exit 1; }
for item in "OPENSSL_VERSION_MAJOR 3" "OPENSSL_VERSION_MINOR 5" "OPENSSL_VERSION_PATCH 9"; do
 set -- $item
 grep -Eq "^[[:space:]]*#[[:space:]]*define[[:space:]]+$1[[:space:]]+$2([[:space:]]|$)" include/openssl/opensslv.h || { echo "FAIL: generated OpenSSL header version mismatch: $item"; exit 1; }
done
stage="provider-smoke-test"
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$test_c" -L"$build/openssl-src" -Wl,-rpath,"$build/openssl-src" -lssl -lcrypto -ldl -pthread -lresolv -o "$out/provider-runtime-test"
LD_LIBRARY_PATH="$build/openssl-src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" OPENSSL_MODULES="$build/openssl-src/providers" OPENSSL_CONF=/dev/null "$out/provider-runtime-test"
REGRESSION_C="$repo/package/mtk/applications/easymesh-n60/tests/test-openssl-api-migration-regressions.c"
REGRESSION_MATRIX="$repo/package/mtk/applications/easymesh-n60/tests/openssl-40-api-regression-matrix.json"
DES_INTERNAL_TEST_C="$repo/package/mtk/applications/easymesh-n60/tests/test-openssl-des-internal-regression.c"
HMAC_TEST_C="$repo/package/mtk/applications/easymesh-n60/tests/test-openssl-hmac-production-regression.c"
HMAC_TEST_PY="$repo/package/mtk/applications/easymesh-n60/tests/test-openssl-hmac-production-regression.py"
test -s "$REGRESSION_C" && test -s "$REGRESSION_MATRIX" && test -s "$DES_INTERNAL_TEST_C" && test -s "$HMAC_TEST_C" && test -s "$HMAC_TEST_PY"
stage="api-family-regressions"
cc -std=c11 -Wall -Wextra -Werror -I"$build/openssl-src/include" "$REGRESSION_C" -L"$build/openssl-src" -Wl,-rpath,"$build/openssl-src" -lcrypto -ldl -pthread -lresolv -o "$out/api-migration-regression-test"
LD_LIBRARY_PATH="$build/openssl-src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" OPENSSL_MODULES="$build/openssl-src/providers" OPENSSL_CONF=/dev/null "$out/api-migration-regression-test" | tee "$out/api-migration-regressions.log"
stage="des-internal-regression"
mapfile -t DES_INTERNAL_SOURCES < <(find "$repo/build_dir" -type f -path '*/easymesh-n60-7.6.7.3/1905daemon/src/crypto/des-internal.c' ! -path '*-openssl-pristine/*' -print | sort)
[[ "${#DES_INTERNAL_SOURCES[@]}" -eq 1 ]] || {
  echo "FAIL: expected exactly one prepared 1905daemon internal DES source; found ${#DES_INTERNAL_SOURCES[@]}" >&2
  printf '%s\n' "${DES_INTERNAL_SOURCES[@]}" >&2
  exit 1
}
DES_INTERNAL_SOURCE="${DES_INTERNAL_SOURCES[0]}"
DES_SOURCE_ROOT="${DES_INTERNAL_SOURCE%/src/crypto/des-internal.c}"
cc -std=gnu11 -Wall -Wextra -Werror -I"$DES_SOURCE_ROOT/inc" -I"$DES_SOURCE_ROOT/src/crypto" "$DES_INTERNAL_TEST_C" "$DES_INTERNAL_SOURCE" -o "$out/des-internal-regression-test"
"$out/des-internal-regression-test" | tee "$out/des-internal-regressions.log"
cat "$out/des-internal-regressions.log" >> "$out/api-migration-regressions.log"
stage="hmac-production-regression"
mapfile -t HMAC_WAPP_SOURCES < <(find "$repo/build_dir" -type f -path '*/easymesh-n60-7.6.7.3/wappd/crypto/crypto_openssl.c' ! -path '*-openssl-pristine/*' -print | sort)
[[ "${#HMAC_WAPP_SOURCES[@]}" -eq 1 ]] || {
  echo "FAIL: expected exactly one prepared WAPP OpenSSL backend source; found ${#HMAC_WAPP_SOURCES[@]}" >&2
  printf '%s\\n' "${HMAC_WAPP_SOURCES[@]}" >&2
  exit 1
}
HMAC_SOURCE_ROOT="${HMAC_WAPP_SOURCES[0]%/wappd/crypto/crypto_openssl.c}"
test -s "$HMAC_SOURCE_ROOT/1905daemon/src/crypto_openssl.c"
test -s "$HMAC_SOURCE_ROOT/1905daemon/src/crypto/crypto.h"
python3 "$HMAC_TEST_PY" \
  --source-root "$HMAC_SOURCE_ROOT" \
  --openssl-include "$build/openssl-src/include" \
  --openssl-lib-dir "$build/openssl-src" \
  --test-harness "$HMAC_TEST_C" \
  --output-dir "$out/hmac-production" \
  --compiler "${CC:-cc}" | tee "$out/hmac-production-regressions.log"
cat "$out/hmac-production-regressions.log" >> "$out/api-migration-regressions.log"
stage="regression-result-aggregation"
python3 - "$REGRESSION_MATRIX" "$REGRESSION_C" "$out/api-migration-regressions.log" "$out/openssl-api-regression-results.json" "$DES_INTERNAL_TEST_C" "$HMAC_TEST_C" "$HMAC_TEST_PY" <<'PY'
import hashlib,json,sys
from pathlib import Path
matrix_path,source_path,log_path,out_path,des_test_source_path,hmac_test_source_path,hmac_test_runner_path=map(Path,sys.argv[1:])
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
        "inputs":{"matrix_sha256":sha(matrix_path),"test_source_sha256":sha(source_path),"des_internal_test_source_sha256":sha(des_test_source_path),"hmac_test_source_sha256":sha(hmac_test_source_path),"hmac_test_runner_sha256":sha(hmac_test_runner_path),"test_log_sha256":sha(log_path)}}
out_path.write_text(json.dumps(result,indent=2)+"\n")
print("PASS: all 40 EasyMesh API entries are covered by the provider-native migration regression suite.")
PY
stage="evidence-checksums"
sha256sum "$test_c" "$REGRESSION_C" "$DES_INTERNAL_TEST_C" "$DES_INTERNAL_SOURCE" "$HMAC_TEST_C" "$HMAC_TEST_PY" "$out/hmac-production/wappd-hmac-production-regression.c" "$out/hmac-production/1905daemon-hmac-production-regression.c" "$out/hmac-production/wappd-hmac-production-regression-test" "$out/hmac-production/1905daemon-hmac-production-regression-test" "$out/provider-runtime-test" "$out/api-migration-regression-test" "$out/des-internal-regression-test" > "$out/SHA256SUMS"
printf '{"openssl_version":"3.5.9","providers":["default","legacy"],"legacy_provider_scope":"regression-test-only","result":"PASS"}\n' > "$out/provider-runtime-result.json"
