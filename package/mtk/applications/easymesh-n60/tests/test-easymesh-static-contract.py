#!/usr/bin/env python3
"""Static contracts for OpenSSL 3, runtime MAC discovery and EasyMesh startup ordering."""
from pathlib import Path
import re
import sys

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

if len(sys.argv) != 3:
    raise SystemExit("usage: test-easymesh-static-contract.py <easymesh-build-dir> <repository-root>")

build = Path(sys.argv[1])
repo = Path(sys.argv[2])
wapp = build / "wappd"
p1905 = build / "1905daemon"
mapd = build / "mapd"
libmapd = build / "libmapd"

# OpenSSL 3 opaque-object contract: vendor code must use public accessors,
# never dereference EVP_PKEY internals or redeclare OpenSSL-owned accessors.
source_roots = [wapp, p1905, mapd, libmapd]
c_sources = []
for root in source_roots:
    require(root.is_dir(), f"required source tree is missing: {root}")
    c_sources.extend(root.rglob("*.c"))
    c_sources.extend(root.rglob("*.h"))
# Direct EVP_PKEY internals are forbidden in active Linux code.
# P1905 has a legacy pkey->pkey.rsa access guarded by CONFIG_NATIVE_WINDOWS;
# it is excluded from the Linux target build and is explicitly recognized.
opaque_hits = []
openssl_files = []
deprecated_counts = {}
for path in c_sources:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"FAIL: cannot read source/header during OpenSSL audit: {path}: {exc}") from exc
    if re.search(r"\b(?:EVP_|EC_KEY|RSA_|DSA_|DH_|HMAC_|SSL_|X509_|ENGINE_|PEM_)", text):
        openssl_files.append(path)
    for match in re.finditer(r"\bpkey\s*->\s*pkey\s*\.\s*(?:ec|rsa|dsa|dh)\b", text):
        line = text.count("\n", 0, match.start()) + 1
        lines = text.splitlines()
        active_windows = False
        conditional_stack = []
        for source_line in lines[:line]:
            directive = source_line.strip()
            if directive.startswith(("#if ", "#ifdef ", "#ifndef ")):
                conditional_stack.append(directive)
            elif directive.startswith("#endif") and conditional_stack:
                conditional_stack.pop()
        active_windows = any("CONFIG_NATIVE_WINDOWS" in item for item in conditional_stack)
        if path.name == "tls_openssl.c" and active_windows:
            continue
        opaque_hits.append(f"{path}:{line}:{match.group(0)}")
    for api in ("EC_KEY_get0_", "EC_KEY_set_", "EVP_PKEY_get1_EC_KEY",
                "EVP_PKEY_set1_EC_KEY", "HMAC_CTX_", "ENGINE_"):
        deprecated_counts[api] = deprecated_counts.get(api, 0) + len(
            re.findall(r"\b" + re.escape(api) + r"\w*\s*\(", text))
require(not opaque_hits, "OpenSSL opaque EVP_PKEY internals remain in Linux-active source: " + "; ".join(opaque_hits[:20]))

dpp_c = (wapp / "dpp/dpp.c").read_text(encoding="utf-8", errors="replace")
dpp_h = (wapp / "dpp/dpp.h").read_text(encoding="utf-8", errors="replace")
require("EVP_PKEY_get0_EC_KEY" in dpp_c,
        "WAPP DPP reconfiguration no longer uses the OpenSSL public EC-key accessor")
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
print(f"PASS: OpenSSL 3 opaque-object audit; {len(openssl_files)} source/header files contain OpenSSL API references.")
print("OpenSSL legacy/deprecated API inventory (reviewed at compile time with visible diagnostics): " +
      ", ".join(f"{name}={count}" for name, count in sorted(deprecated_counts.items())))

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
