#!/usr/bin/env python3
"""Static contracts for OpenSSL 3, runtime MAC discovery and EasyMesh startup ordering."""
from pathlib import Path
import re
import subprocess
import sys

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

if len(sys.argv) != 3:
    raise SystemExit("usage: test-easymesh-static-contract.py <easymesh-build-dir> <repository-root>")

build = Path(sys.argv[1])
repo = Path(sys.argv[2])

# The archive extraction in native Package Prepare creates these three
# source roots directly beneath PKG_BUILD_DIR. Resolve them once here so
# every static contract reads the exact prepared source tree.
wapp = build / "wappd"
p1905 = build / "1905daemon"
mapd = build / "mapd"
libmapd = build / "libmapd"
for label, source_root in (("WAPP", wapp), ("P1905", p1905), ("MAPD", mapd),
                           ("libmapd", libmapd)):
    require(source_root.is_dir(), f"{label} source root is missing from prepared build tree: {source_root}")

# Regression: GNU Make consumes dollar references inside recipes. The
# OpenSSL-major ERE must preserve its end-of-line anchor through nested Make
# expansion, otherwise grep receives an unmatched opening parenthesis.
package_makefile = (repo / "package/mtk/applications/easymesh-n60/Makefile").read_text(encoding="utf-8")
# Build/Prepare is expanded through BuildPackage/eval and the package recipe.
# Shell variables introduced there therefore need four dollars in source;
# two dollars are consumed by GNU Make nested expansion and otherwise
# silently turn $OPENSSL... / $component into PENSSL... / omponent.
prepare_lines = package_makefile.split("define Build/Prepare", 1)[1].split("endef", 1)[0]
for shell_ref in ("OPENSSL_AUDIT_PRISTINE", "component"):
    require(("$$" + shell_ref) in prepare_lines,
            "nested Build/Prepare shell variable must use four-dollar Make escaping: " + shell_ref)
openssl_check = next((line for line in package_makefile.splitlines()
                      if "OPENSSL_VERSION_MAJOR" in line and "grep -Eq" in line), "")
dollar4 = chr(36) * 4
require(f"([[:space:]]|{dollar4})'" in openssl_check,
        "OpenSSL major-version recipe must escape the ERE end anchor four times for nested GNU Make")
# Model the two Make expansion passes and verify the exact ERE accepts a
# canonical OpenSSL 3 header declaration without a syntax error.
expanded_check = openssl_check.replace(dollar4, chr(36))
match = re.search(r"grep -Eq '([^']+)'", expanded_check)
require(match is not None, "cannot extract OpenSSL major-version ERE after Make expansion")
# The Makefile expression is POSIX ERE, not Python's regex dialect.
# Use the same grep -E engine as the native Build/Prepare recipe so POSIX
# character classes such as [[:space:]] are tested without false warnings.
valid_header = "# define OPENSSL_VERSION_MAJOR  3\n"
ere_result = subprocess.run(
    ["grep", "-Eq", match.group(1)],
    input=valid_header,
    text=True,
    capture_output=True,
    check=False,
)
require(ere_result.returncode == 0,
        "OpenSSL major-version POSIX ERE rejects a valid OpenSSL 3 header"
        + (": " + ere_result.stderr.strip() if ere_result.stderr.strip() else ""))
invalid_ere = subprocess.run(
    ["grep", "-Eq", "[[:space:]"],
    input=valid_header,
    text=True,
    capture_output=True,
    check=False,
)
require(invalid_ere.returncode == 2,
        "regression: invalid POSIX ERE was not rejected by grep -E")
nonmatching_header = subprocess.run(
    ["grep", "-Eq", match.group(1)],
    input="# define OPENSSL_VERSION_MAJOR  4\n",
    text=True,
    capture_output=True,
    check=False,
)
require(nonmatching_header.returncode == 1,
        "OpenSSL major-version POSIX ERE must reject a non-3 major version")

dpp_c = (wapp / "dpp/dpp.c").read_text(encoding="utf-8", errors="replace")
dpp_h = (wapp / "dpp/dpp.h").read_text(encoding="utf-8", errors="replace")
require("EC_KEY * EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)" not in dpp_c,
        "vendor still defines an OpenSSL-owned EVP_PKEY accessor")
require("EVP_PKEY_get0_EC_KEY" not in dpp_h,
        "vendor header still redeclares an OpenSSL-owned EVP_PKEY accessor")
require((wapp / "crypto/crypto_openssl.c").is_file(),
        "WAPP OpenSSL crypto backend is missing")
require((p1905 / "src/crypto_openssl.c").is_file(),
        "P1905 OpenSSL crypto backend is missing")
require((p1905 / "src/dpp.c").is_file(),
        "P1905 DPP/OpenSSL source is missing")
# Full OpenSSL API inventory and provider runtime checks are explicit,
# independent gates. Do not turn a file-count heuristic into a migration verdict.
openssl_pkg = repo / "package/libs/openssl/Makefile"
inventory_test = repo / "package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory.py"
inventory_selftest = repo / "package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory-selftest.py"
provider_test = repo / "package/mtk/applications/easymesh-n60/tests/test-openssl-provider-runtime.c"
provider_runner = repo / "package/mtk/applications/easymesh-n60/scripts/run-openssl-provider-runtime.sh"
api_policy = repo / "package/mtk/applications/easymesh-n60/tests/openssl-api-policy.json"
openssl_package_text = openssl_pkg.read_text(encoding="utf-8")
require(re.findall(r"(?m)^PKG_VERSION:=(\S+)\s*$", openssl_package_text) == ["3.5.9"],
        "OpenSSL migration audit must pin exactly OpenSSL 3.5.9")
quick_workflow = repo / ".github/workflows/quick-prepare-audit.yml"
quick_workflow_text = quick_workflow.read_text(encoding="utf-8")
prepare_pos = quick_workflow_text.find("Run native Build Prepare for all fixed vendor packages")
wifi026_pos = quick_workflow_text.find("Assert MT Wi-Fi 026 after Quick Prepare")
provider_pos = quick_workflow_text.find("Run Provider-native OpenSSL 3.5.9 runtime regression tests")
inventory_pos = quick_workflow_text.find("Enforce strict OpenSSL 3.5.9 API migration and const-correctness gate")
host_decompressor_pos = quick_workflow_text.find("Build the OpenWrt host decompressor required by native OpenSSL Prepare")
require(min(host_decompressor_pos, prepare_pos, wifi026_pos, provider_pos, inventory_pos) >= 0 and
        host_decompressor_pos < prepare_pos < wifi026_pos < provider_pos < inventory_pos,
        "OpenWrt libdeflate host tool must be installed before native OpenSSL Prepare and OpenSSL audits must remain after MT Wi-Fi 026")
host_decompressor_step = quick_workflow_text[host_decompressor_pos:prepare_pos]
require("make tools/libdeflate/compile V=s" in host_decompressor_step and
        "test -x staging_dir/host/bin/libdeflate-gzip" in host_decompressor_step,
        "Quick Prepare must build and verify the exact libdeflate-gzip host tool before native OpenSSL extraction")
require("test-openssl-api-inventory.py" not in package_makefile and
        "test-openssl-api-inventory-selftest.py" not in package_makefile,
        "strict OpenSSL inventory is duplicated inside EasyMesh Build/Prepare before MT Wi-Fi 026")
for rel in ("tests/test-openssl-api-inventory.py", "tests/test-openssl-api-inventory-selftest.py",
            "tests/openssl-api-policy.json", "tests/test-openssl-provider-runtime.c",
            "scripts/run-openssl-provider-runtime.sh"):
    require(rel in quick_workflow_text,
            f"Quick Prepare does not explicitly preflight/use OpenSSL audit input: {rel}")
runtime_step = quick_workflow_text[provider_pos:inventory_pos]
strict_step = quick_workflow_text[inventory_pos:quick_workflow_text.find("Upload OpenSSL API inventory", inventory_pos)]
require("continue-on-error: true" in runtime_step and
        "steps.openssl_provider_runtime.outcome == 'failure'" in quick_workflow_text,
        "Provider runtime continue-on-error is not paired with an explicit failing outcome gate")
require("--strict" in strict_step and "continue-on-error:" not in strict_step,
        "strict OpenSSL API inventory failure must fail the job and cannot be continue-on-error")
print("PASS: OpenSSL 3.5.9 gates are ordered after Prepare and MT Wi-Fi 026; inventory/runtime failures remain fatal.")

# Runtime MAC contract: AL MAC comes from the selected live interface;
# WAPP obtains BSSID from the driver's BSS-info response. FF:FF... in WTS
# is a vendor wildcard placeholder, not a device-specific MAC.
pkg = repo / "package/mtk/applications/easymesh-n60"
cfg = (pkg / "files/etc/map/1905d.cfg").read_text(encoding="utf-8")
init = (pkg / "files/etc/init.d/easymesh").read_text(encoding="utf-8")
wdev = (wapp / "common/wdev.c").read_text(encoding="utf-8", errors="replace")
driver = (wapp / "common/driver_wext.c").read_text(encoding="utf-8", errors="replace")
wdev_ap = (wapp / "common/wdev_ap.c").read_text(encoding="utf-8", errors="replace")
wts = (pkg / "files/etc/map/wts_bss_info_config").read_text(encoding="utf-8")
require(re.search(r"^al_inf=rax0$", cfg, re.M) is not None,
        "N60 AL interface must remain the configured dynamic wireless interface rax0")
require(not re.search(r"^map_(?:controller|agent)_alid=", cfg, re.M),
        "N60 runtime config hardcodes an AL MAC")
require('cat "/sys/class/net/$al_inf/address"' in init,
        "init does not obtain the AL MAC from the live interface address")
require("OID_GET_BSS_INFO" in driver and "driver_wext_get_oid" in driver and
        ".drv_get_bss_info = driver_wext_get_bss_info" in driver,
        "WAPP WEXT driver operations do not expose the live BSS-info query")
require("WAPP_BSS_INFO_QUERY_REQ" in wdev_ap and
        "wdev_bss_info_query_rsp_handle" in wdev_ap,
        "WAPP AP interface initialization does not request/consume live BSS information")
require("wdev_bss_info_query_rsp_handle" in wdev and
        "bss_info_rcvd" in wdev and "op_bss_table[idx] = *bss_info" in wdev,
        "WAPP does not cache the driver's returned BSSID in its operational BSS table")
require(bool(re.search(r"(?m)^\d+,ff:ff:ff:ff:ff:ff\s", wts)),
        "N60 WTS vendor wildcard placeholder rows are missing")
require(not re.search(r"(?m)^\d+,(?!ff:ff:ff:ff:ff:ff)(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\s", wts),
        "N60 WTS contains a device-specific unicast BSSID instead of the vendor wildcard")
print("PASS: AL MAC is read from the live ra/rax interface; BSSID is obtained from WAPP driver BSS-info; WTS uses vendor wildcard placeholders.")

# WTS security contract: keep the vendor reader and record format, while
# requiring bounded input, bounded tokens, fail-closed parsing and redacted logs.
wts_wapp = (wapp / "common/main.c").read_text(encoding="utf-8", errors="replace")
wts_wapp_map = (wapp / "map/map_1905.c").read_text(encoding="utf-8", errors="replace")
wts_wdev = (wapp / "common/wdev.c").read_text(encoding="utf-8", errors="replace")
wts_p1905 = (p1905 / "src/file_io.c").read_text(encoding="utf-8", errors="replace")
wts_p1905_map = (p1905 / "src/multi_ap.c").read_text(encoding="utf-8", errors="replace")
wts_mapd = (mapd / "src/topologySrv/topologySrv.c").read_text(encoding="utf-8", errors="replace")
require("while ((ch = fgetc(f)) != EOF)" in wts_wapp and
        "if (i >= content_len - 1)" in wts_wapp and "content[i] = '\\0';" in wts_wapp,
        "WAPP vendor WTS reader lacks pre-write bounds or a terminating NUL")
require('os_strlen(pos1) >= sizeof(op_class)' in wts_wapp and
        'os_strlen(pos1) >= sizeof(ssid)' in wts_wapp and
        'os_strlen(pos1) >= sizeof(key)' in wts_wapp,
        "WAPP WTS token length guards are incomplete")
require('if (ret != 6)' in wts_wapp and wts_wapp.count('if (ret != 1)') >= 6,
        "WAPP WTS scanf conversion results are not checked exactly")

def require_wts_record_limit(source, marker, label):
    start = source.find(marker)
    require(start >= 0, f"{label}: WTS parser capacity declaration is missing")
    terminator = source.find("content[i] = '\\0';", start)
    require(terminator > start, f"{label}: WTS input is not NUL-terminated before parsing")
    loop_match = re.search(r"\b(?:while|for)\s*\(", source[terminator:])
    require(loop_match is not None, f"{label}: WTS record parser loop is missing")
    loop = terminator + loop_match.start()
    first_access = source.find("bss_info[i]", loop)
    require(first_access > loop, f"{label}: indexed BSS record write is missing")
    guard = source.find("if (i >= max_bss_num)", loop, first_access)
    bounded_loop = re.search(
        r"\b(?:while|for)\s*\([^)]*\bi\s*<\s*max_bss_num",
        source[loop:first_access]
    ) is not None
    excerpt = source[loop:first_access + 120]
    require(guard >= 0 or bounded_loop,
            f"{label}: record count is not bounded before bss_info[i] access; excerpt={excerpt!r}")

require_wts_record_limit(wts_wapp, "content_len = WTS_FILE_READ_LINE * max_bss_num;", "WAPP")
require_wts_record_limit(wts_p1905, "content_len = 100 * max_bss_num;", "P1905")

p1905_func = wts_p1905.find("int _1905_read_set_config(")
require(p1905_func >= 0, "P1905 WTS parser function is missing")
p1905_body = wts_p1905[p1905_func:]
p1905_err = p1905_body.find("\nerr:")
require(p1905_err >= 0, "P1905 WTS parser error label is missing")
p1905_error_body = p1905_body[p1905_err:]
require("os_memset(bss_info, 0, sizeof(*bss_info) * max_bss_num);" in p1905_error_body and
        "*config_bss_num = 0;" in p1905_error_body,
        "P1905 malformed input must clear partial BSS output and reset the returned count")
require("pending_primary_vid = vid;" in p1905_body and
        "pending_pcp = pcp;" in p1905_body and
        "pending_tpolicy_updated = 1;" in p1905_body and
        "ctx->map_policy.setting.primary_vid = pending_primary_vid;" in p1905_body and
        "ctx->map_policy.setting.dft.PCP = pending_pcp;" in p1905_body and
        "ctx->map_policy.tpolicy.updated = pending_tpolicy_updated;" in p1905_body,
        "P1905 MAP-R2 state must be staged and committed only after successful parsing")
fclose_pos = p1905_body.find("if (fclose(f) < 0)")
commit_pos = p1905_body.find("ctx->map_policy.setting.primary_vid = pending_primary_vid;")
require(fclose_pos >= 0 and commit_pos > fclose_pos,
        "P1905 MAP-R2 state must not be committed before the input file closes successfully")
for field_error in ("index not found", "mac not found", "opclass not found", "ssid not found",
                    "authmode not found", "encrytype not found", "key not found", "resv1 not found",
                    "end line not found"):
    pos = p1905_body.find(field_error)
    block_end = p1905_body.find("}", pos)
    field_block = p1905_body[pos:block_end + 1] if pos >= 0 and block_end >= 0 else ""
    require("goto err;" in field_block and "break;" not in field_block,
            f"P1905 malformed mandatory field must fail closed: {field_error}")
print("PASS: P1905 WTS malformed-field rollback and MAP-R2 state transaction.")
print("PASS: WAPP and P1905 WTS record counts are bounded before indexed BSS writes.")

require('goto err;' in wts_wapp and '*config_bss_num = 0;' in wts_wapp,
        "WAPP WTS malformed-input path does not fail closed/reset outputs")
require('while ((ch = fgetc(f)) != EOF)' in wts_p1905 and
        'if (i >= content_len - 1)' in wts_p1905 and "content[i] = '\\0';" in wts_p1905,
        "P1905 vendor WTS reader lacks pre-write bounds, int EOF handling or NUL termination")
require('sscanf(pos1, "%d", &resv2) != 1' in wts_p1905,
        "P1905 WTS reserved-field conversion check remains ineffective")
for source, label in ((wts_wapp, "WAPP WTS"), (wts_wapp_map, "WAPP MAP"),
                      (wts_wdev, "WAPP PSK"), (wts_p1905, "P1905 WTS"),
                      (wts_p1905_map, "P1905 BSS"), (wts_mapd, "MAPD topology")):
    require(not re.search(r"key=%s|psk = %s", source),
            label + " diagnostic still prints a Wi-Fi secret")
require("key is configured" in wts_wapp and "key is configured" in wts_p1905 and
        "key is configured" in wts_p1905_map and "key is configured" in wts_mapd,
        "Wi-Fi secret-redaction markers are incomplete")
require('key = %s' not in wts_wdev,
        "WAPP WPS configuration handler still logs the plaintext credential")

print("PASS: vendor WTS readers retain the original field flow; bounded reads/tokens, fail-closed errors and WAPP/P1905/MAPD secret redaction are enforced.")

# Startup contract: init starts WAPP, then P1905; MAPD's own source performs
# WAPP and P1905 control-socket connection/retry before topology initialization.
mapd_main = (mapd / "mapd.c").read_text(encoding="utf-8", errors="replace")
mapd_1905 = (mapd / "src/1905_if/1905_if.c").read_text(encoding="utf-8", errors="replace")
p1905_ctrl = (p1905 / "src/_1905_interface_ctrl.c").read_text(encoding="utf-8", errors="replace")
p1905_multi_ap = (p1905 / "src/multi_ap.c").read_text(encoding="utf-8", errors="replace")
require(init.find("procd_set_param command /usr/bin/wapp-n60-wrapper") <
        init.find("procd_set_param command /bin/sh -c", init.find("procd_set_param command /usr/bin/wapp-n60-wrapper")) <
        init.find("generate-mapd-strng"),
        "init service order is not WAPP -> P1905 -> MAPD")
require("while (_1905_open_connection(\"map_daemon\", global) != 0)" in mapd_main,
        "MAPD no longer retries its P1905 control connection")
require("while (ret != 0)" in mapd_main and "wapp_open_connection(\"/tmp/wapp_ctrl\", global)" in mapd_main,
        "MAPD no longer retries its WAPP control connection")
require('"1905_daemon"' in p1905_ctrl and 'ATTACH:%s' in p1905_ctrl,
        "P1905 abstract control socket/ATTACH handshake contract changed")
require("int common_info_init(" in p1905_multi_ap and
        "os_memcmp(ctx->al_inf, ctx->itf[i].if_name, IFNAMSIZ)" in p1905_multi_ap and
        "os_memcpy(ctx->p1905_al_mac_addr, ctx->itf[i].mac_addr, ETH_ALEN)" in p1905_multi_ap,
        "P1905 does not derive its AL MAC from the live interface selected by al_inf")
require("wapp_server" in init and "wapp_ctrl" in init,
        "P1905 launch no longer waits for WAPP event/control sockets")
require("@1905_daemon" in init and "did not become ready within 30 seconds" in init,
        "MAPD launch does not wait for the P1905 abstract control socket")
print("PASS: startup dependency chain and MAPD WAPP/P1905 control-socket retry/ATTACH behavior are source-verified.")
