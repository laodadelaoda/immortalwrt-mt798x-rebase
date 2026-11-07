#!/usr/bin/env python3
"""Semantic source-contract checks for the N60 Pro WAPP DPP path."""
from pathlib import Path
import re
import sys

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

if len(sys.argv) != 2:
    raise SystemExit("usage: test-dpp-source-contract.py <easymesh-build-dir>")

root = Path(sys.argv[1])
paths = {
    "main": root / "wappd/common/main.c",
    "map": root / "wappd/map/map_1905.c",
    "dpp": root / "wappd/dpp/dpp.c",
    "header": root / "wappd/dpp/dpp.h",
    "wdev": root / "wappd/common/wdev.c",
    "dpp_wdev": root / "wappd/dpp/dpp_wdev.c",
}
for name, path in paths.items():
    require(path.is_file(), f"required DPP source is missing: {path}")
src = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}

main = src["main"]
start = main.find("int dpp_read_config_file_for_connection")
require(start >= 0, "DPP connection-config parser is missing")
end = main.find("\n}\n", start)
require(end >= 0, "DPP connection-config parser has no closing function brace")
parser = main[start:end + 3]

null_guard = parser.find("if (!wapp)")
list_access = parser.find("dev_list = &wapp->dev_list")
require(null_guard >= 0 and list_access > null_guard,
        "WAPP pointer must be validated before dereferencing its device list")

auth_init = parser.find("os_memset(&auth, 0, sizeof(auth));")
first_key = parser.find('"_1905netAccessKey"')
require(auth_init >= 0 and first_key > auth_init,
        "DPP authentication state must be zero-initialized before allocating credential buffers")
connector_alloc = parser.find("auth.connector = os_zalloc(")
connector_guard = parser.find("if (!auth.connector)", connector_alloc)
require(connector_alloc >= 0 and connector_guard > connector_alloc,
        "DPP connector allocation must be checked before use")


def check_hex_key(begin_marker, end_marker, field_name):
    begin = parser.find(begin_marker)
    require(begin >= 0, f"{field_name}: source parameter lookup is missing")
    end = parser.find(end_marker, begin) if end_marker else parser.find(
        "cred = wapp_dpp_save_dpp_cred", begin)
    require(end > begin, f"{field_name}: key parser block boundary is missing")
    block = parser[begin:end]
    for token in (
        "get_dpp_parameters(wapp->map, param, value, sizeof(value)) < 0",
        "size_t hex_len = os_strlen(value)",
        "(hex_len & 1)",
        "hex_len / 2 > sizeof(buf_temp)",
        "key_len = hex_len / 2",
        "hexstr2bin(value, buf_temp, key_len) < 0",
        f"auth.{field_name} = wpabuf_alloc(key_len)",
        f"NdisCopyMemory(auth.{field_name}->buf, buf_temp, key_len)",
        f"auth.{field_name}->used = key_len",
    ):
        require(token in block, f"{field_name}: missing checked conversion invariant: {token}")
    alloc = block.find(f"auth.{field_name} = wpabuf_alloc(key_len)")
    guard = block.find(f"if (!auth.{field_name})", alloc)
    copy = block.find(f"NdisCopyMemory(auth.{field_name}->buf, buf_temp, key_len)", guard)
    require(alloc >= 0 and guard > alloc and copy > guard,
            f"{field_name}: wpabuf allocation must be checked before copying key bytes")
    zero = block.find("NdisZeroMemory(value")
    used = block.find(f"auth.{field_name}->used = key_len")
    require(zero < 0 or zero > used,
            f"{field_name}: source hex string is cleared before the key copy is complete")
    buf_zero = block.find("NdisZeroMemory(buf_temp")
    require(buf_zero < 0 or buf_zero > used,
            f"{field_name}: temporary decoded key buffer is cleared before the key copy is complete")

check_hex_key('"_1905netAccessKey"', '"_1905cSignKey"', "net_access_key")
check_hex_key('"_1905cSignKey"', None, "c_sign_key")

require("dpp_read_config_file_for_connection(wapp) < 0" in src["map"],
        "MAP event handler ignores DPP parser failure")
require("ret = MAP_ERROR" in src["map"],
        "MAP event handler does not propagate DPP parser failure")

get_start = main.find("int get_dpp_parameters(")
require(get_start >= 0, "DPP parameter accessor is missing")
get_end = main.find("\n}\n", get_start)
require(get_end >= 0, "DPP parameter accessor has no closing brace")
get_fn = main[get_start:get_end + 3]
require("if (len >= val_len)" in get_fn and
        "os_memcpy(value, tmp_value, len + 1)" in get_fn,
        "OpenWrt KVC accessor must reject truncation and copy a bounded NUL-terminated value")

require("EVP_PKEY_get0_EC_KEY" not in src["header"],
        "local EVP_PKEY_get0_EC_KEY prototype conflicts with OpenSSL 3 native declaration")
require("EC_KEY * EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)" not in src["dpp"],
        "vendor EVP_PKEY_get0_EC_KEY implementation still accesses opaque EVP_PKEY internals")
require("EVP_PKEY_get0_EC_KEY(csign)" in src["dpp"],
        "DPP reconfiguration path no longer uses the native OpenSSL EC-key accessor")
require('DPP_MAP_PREX"dpp_private_key=%s' not in src["dpp"],
        "DPP private-key debug logging is not redacted")

for name in ("main", "dpp", "wdev", "dpp_wdev"):
    source = src[name]
    for secret_log in (
        "pass :%s",
        "passphrase(%d, len:%ld): %s",
        "passphrase = %s",
        "passphrases = %s",
    ):
        require(secret_log not in source,
                f"{name}: credential logging regression: {secret_log}")


# Per-interface DPP config copies must never retain pointers into the temporary source config.
copy_start = parser.find("os_memcpy(wdev->config, (char *)(&config[k])")
require(copy_start >= 0, "per-interface DPP config copy is missing")
copy_end = parser.find("wdev->config->key_mgmt = WPA_KEY_MGMT_DPP", copy_start)
require(copy_end > copy_start, "per-interface DPP config copy block is incomplete")
copy_block = parser[copy_start:copy_end]
for field in ("ssid", "dpp_connector", "dpp_csign", "dpp_netaccesskey"):
    require(f"wdev->config->{field} = NULL;" in copy_block,
            f"{field}: shallow source pointer is not cleared before the owned copy")
for field in ("dpp_csign", "dpp_netaccesskey", "ssid", "dpp_connector", "dpp_ppkey"):
    alloc = copy_block.find(f"wdev->config->{field} = os_zalloc")
    if alloc >= 0:
        check = copy_block.find(f"if (!wdev->config->{field})", alloc)
        memcpy = copy_block.find(f"os_memcpy(wdev->config->{field}", check)
        require(check > alloc and memcpy > check,
                f"{field}: allocation result is not checked before copying")
require("wdev_config_error:" in parser and "goto wdev_config_error;" in parser,
        "per-interface allocation failure has no rollback path")
for field in ("ssid", "dpp_connector", "dpp_csign", "dpp_netaccesskey"):
    require(f"os_free(wdev->config->{field})" in parser,
            f"{field}: per-interface rollback does not release partial allocation")
for field in ("ssid_len", "dpp_csign_len", "dpp_netaccesskey_len", "dpp_ppkey_len"):
    require(f"wdev->config->{field} = 0;" in parser,
            f"{field}: per-interface rollback leaves a stale length after freeing its buffer")
require(re.search(r"} else {\n[ \t]+goto error;", parser) is not None,
        "failure to allocate the per-interface dpp_config object is silently ignored")


# Audit every DPP configuration-file/QR path that is active in MAP R3.
dpp_wdev = src["dpp_wdev"]
conf_start = dpp_wdev.find("int wapp_dpp_get_conf_frm_file(")
conf_end = dpp_wdev.find("\\nstatic int wapp_dpp_read_qr_count", conf_start)
require(conf_start >= 0 and conf_end > conf_start,
        "DPP config-file accessor function boundary is missing")
conf_fn = dpp_wdev[conf_start:conf_end]
require("char param[64] = {0}, value[64] = {0};" in conf_fn,
        "DPP config-file accessor reads an uninitialized value buffer")
require("if (!wapp || !wapp->map || !str)" in conf_fn and
        "get_dpp_parameters(wapp->map, param, value, sizeof(value)) < 0" in conf_fn,
        "DPP config-file accessor lacks NULL and parameter-read failure guards")

qr_helper_start = dpp_wdev.find("static int wapp_dpp_read_qr_count(")
qr_helper_end = dpp_wdev.find("\\nvoid wapp_dpp_get_uri_frm_file", qr_helper_start)
require(qr_helper_start >= 0 and qr_helper_end > qr_helper_start,
        "WAPP QR count helper is missing")
qr_helper = dpp_wdev[qr_helper_start:qr_helper_end]
for token in ("len > 3", "value[i] < '0'", "value[i] > '9'",
              "parsed > MAP_MAX_DPP_URI_COUNT", "*count = parsed"):
    require(token in qr_helper, "WAPP QR count validation is incomplete: " + token)
qr_start = dpp_wdev.find("void wapp_dpp_get_uri_frm_file(")
qr_end = dpp_wdev.find("\\n#endif /* MAP_R3 */", qr_start)
require(qr_start >= 0 and qr_end > qr_start, "WAPP QR restore function boundary is missing")
qr_fn = dpp_wdev[qr_start:qr_end]
require("unsigned int uri_num = 1, uri_cnt = 0;" in qr_fn and
        "wapp_dpp_read_qr_count(wapp, &uri_cnt) < 0" in qr_fn,
        "WAPP QR restore loop lacks bounded unsigned count handling")
require("get_dpp_parameters(wapp->map, qr_param, value, sizeof(value)) < 0" in qr_fn,
        "WAPP QR restore ignores a failed parameter read")

dpp_source = src["dpp"]
count_helper_start = dpp_source.find("static int dpp_read_qr_count(")
count_helper_end = dpp_source.find("\\nint  dpp_reset_dpp_config_file", count_helper_start)
require(count_helper_start >= 0 and count_helper_end > count_helper_start,
        "DPP QR count helper is missing")
count_helper = dpp_source[count_helper_start:count_helper_end]
for token in ("len > 3", "value[i] < '0'", "value[i] > '9'",
              "parsed > MAP_MAX_DPP_URI_COUNT", "*count = parsed"):
    require(token in count_helper, "DPP QR count validation is incomplete: " + token)
reset_start = dpp_source.find("int  dpp_reset_dpp_config_file(")
reset_end = dpp_source.find("\\nint  dpp_reset_mapd_user_config_file", reset_start)
require(reset_start >= 0 and reset_end > reset_start, "DPP reset function boundary is missing")
reset_fn = dpp_source[reset_start:reset_end]
require("dpp_read_qr_count(wapp, &uri_cnt) < 0" in reset_fn and
        "uri_cnt = 0;" in reset_fn and "char uri_num" not in reset_fn,
        "DPP reset does not safely bound QR cleanup iteration")
remove_start = dpp_source.find("void  dpp_remove_uri_from_file(")
remove_end = dpp_source.find("\\nstatic int dpp_bootstrap_del", remove_start)
require(remove_start >= 0 and remove_end > remove_start, "DPP URI removal function boundary is missing")
remove_fn = dpp_source[remove_start:remove_end]
require("!wapp || !wapp->map || !wapp->dpp || !uri_temp" in remove_fn and
        "dpp_read_qr_count(wapp, &uri_cnt) < 0" in remove_fn and
        "unsigned int uri_num = 1, uri_cnt = 0;" in remove_fn,
        "DPP URI removal lacks NULL guards and bounded unsigned QR iteration")
require(remove_fn.count("get_dpp_parameters(wapp->map, qr_param, value, sizeof(value)) < 0") >= 3,
        "DPP URI removal ignores a QR entry read failure")

print("PASS: DPP parser bounds, hex decoding lengths, error propagation, OpenSSL 3 accessor and secret redaction")
