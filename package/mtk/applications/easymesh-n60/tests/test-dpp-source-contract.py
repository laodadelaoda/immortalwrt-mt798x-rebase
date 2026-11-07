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

dpp_source_files = list((root / "wappd/dpp").rglob("*.c")) + list((root / "wappd/dpp").rglob("*.h"))
for source_path in dpp_source_files:
    source_text = source_path.read_text(encoding="utf-8")
    require(re.search(r"\b(?:pkey|key)->pkey\.", source_text) is None,
            f"OpenSSL opaque EVP_PKEY field access remains in {source_path}")
    require(re.search(r"\bEVP_PKEY_get0_EC_KEY\s*\([^;]*\)\s*\{", source_text, re.S) is None,
            f"vendor EVP_PKEY_get0_EC_KEY implementation shadows OpenSSL 3 in {source_path}")

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



conf_start = src["dpp_wdev"].find("int wapp_dpp_get_conf_frm_file(")
conf_end = src["dpp_wdev"].find("\nvoid wapp_dpp_get_uri_frm_file", conf_start)
require(conf_start >= 0 and conf_end > conf_start,
        "DPP config-file accessor function boundary is missing")
conf_fn = src["dpp_wdev"][conf_start:conf_end]
require("char param[64] = {0}, value[64] = {0};" in conf_fn and
        "if (!wapp || !wapp->map || !str)" in conf_fn and
        "get_dpp_parameters(wapp->map, param, value, sizeof(value)) < 0" in conf_fn,
        "DPP config-file accessor lacks initialized output, NULL guard or error handling")


def extract_c_function(source, signature):
    start = source.find(signature)
    require(start >= 0, f"missing C function: {signature}")
    brace = source.find("{", start)
    require(brace > start, f"missing function body: {signature}")
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    require(False, f"unterminated C function: {signature}")


require("#define MAP_MAX_DPP_URI_COUNT 100" in src["header"],
        "DPP QR source limit changed unexpectedly")
qr_param_fn = extract_c_function(src["dpp"], "int dpp_read_qr_parameter(")
for token in ("dat_load(DPP_CFG_FILE)", "if (!dat_ctx)", "kvc_get(dat_ctx, param)",
              "if (!stored)", "ret = 1", "if (len >= value_len)",
              "os_memcpy(value, stored, len + 1)", "kvc_unload(dat_ctx)"):
    require(token in qr_param_fn, f"DPP QR parameter reader lacks invariant: {token}")

qr_count_fn = extract_c_function(src["dpp"], "int dpp_read_qr_count(")
for token in ('"qr_count"', "ret == 1", "ret < 0", "len > 3",
              "value[i] < '0'", "value[i] > '9'",
              "parsed > MAP_MAX_DPP_URI_COUNT", "*count = parsed"):
    require(token in qr_count_fn, f"DPP QR count parser lacks invariant: {token}")

def qr_count_reference(value):
    if value is None:
        return 0
    if not value or len(value) > 3:
        return None
    parsed = 0
    for char in value:
        if char < "0" or char > "9":
            return None
        parsed = parsed * 10 + ord(char) - ord("0")
        if parsed > 100:
            return None
    return parsed

for raw, expected in ((None, 0), ("0", 0), ("1", 1), ("100", 100), ("000", 0)):
    require(qr_count_reference(raw) == expected,
            f"DPP QR count reference parser rejected valid boundary {raw!r}")
for raw in ("", "101", "1000", "-1", "+1", " 1", "1x"):
    require(qr_count_reference(raw) is None,
            f"DPP QR count reference parser accepted invalid value {raw!r}")

qr_load_fn = extract_c_function(src["dpp_wdev"], "void wapp_dpp_get_uri_frm_file(")
require("if (!wapp || !wapp->map || !wapp->dpp)" in qr_load_fn and
        "dpp_read_qr_count(wapp, &uri_cnt) < 0" in qr_load_fn and
        "unsigned int uri_num, uri_cnt = 0;" in qr_load_fn and
        "dpp_read_qr_parameter(wapp, qr_param, value, sizeof(value))" in qr_load_fn and
        "if (ret < 0)" in qr_load_fn and "atoi(value)" not in qr_load_fn and
        "char uri_num" not in qr_load_fn,
        "DPP QR load path lacks bounded count, NULL checks or read-error handling")

qr_reset_fn = extract_c_function(src["dpp"], "int  dpp_reset_dpp_config_file(")
require("if (!wapp || !wapp->map)" in qr_reset_fn and
        "dpp_read_qr_count(wapp, &uri_cnt) < 0" in qr_reset_fn and
        "unsigned int uri_num, uri_cnt = 0;" in qr_reset_fn and
        "dpp_delete_parameter_from_file(wapp, qr_param) < 0" in qr_reset_fn and
        "atoi(value)" not in qr_reset_fn and "char uri_num" not in qr_reset_fn,
        "DPP QR reset path lacks bounded count or checked deletion")
require("char *ifparam = NULL;" in qr_reset_fn and
        "ret = -1;" in qr_reset_fn and
        "NdisZeroMemory(ifparam, os_strlen(param) + 1);" in qr_reset_fn,
        "DPP config reset allocation failure or NUL termination is unsafe")

qr_remove_fn = extract_c_function(src["dpp"], "void  dpp_remove_uri_from_file(")
require("if (!wapp || !wapp->map || !wapp->dpp || !uri_temp || !uri_temp[0])" in qr_remove_fn and
        "dpp_read_qr_count(wapp, &uri_cnt) < 0" in qr_remove_fn and
        "os_strlen(uri_temp) >= 150" in qr_remove_fn and
        "unsigned int uri_cnt = 0, uri_num, found = 0;" in qr_remove_fn and
        "os_zalloc(sizeof(*uri_values) * uri_cnt)" in qr_remove_fn and
        "os_strcmp(uri_temp, uri_values[uri_num - 1]) == 0" in qr_remove_fn and
        "memcmp(uri_temp" not in qr_remove_fn and "atoi(value)" not in qr_remove_fn and
        "char uri_num" not in qr_remove_fn and "dpp_save_config(wapp, qr_param, uri_values[uri_num - 1], NULL) < 0" in qr_remove_fn and
        "dpp_delete_parameter_from_file(wapp, qr_param) < 0" in qr_remove_fn and
        "wapp->dpp->qr_code_num = (u8)(uri_cnt - 1);" in qr_remove_fn and
        "os_free(uri_values);" in qr_remove_fn,
        "DPP QR remove path lacks bounded full-list read, exact comparison or checked updates")

qr_save_fn = extract_c_function(src["dpp_wdev"], "void dpp_save_dpp_uri_to_file(")
require("if (!wapp || !wapp->map || !wapp->dpp || !uri_str || !uri_str[0])" in qr_save_fn and
        "os_strlen(uri_str) >= 150" in qr_save_fn and
        "dpp_read_qr_count(wapp, &current_count) < 0" in qr_save_fn and
        "current_count >= MAP_MAX_DPP_URI_COUNT ? 1 : current_count + 1" in qr_save_fn and
        "dpp_save_config(wapp, qr_param, uri_str, NULL) < 0" in qr_save_fn and
        'dpp_save_config(wapp, "qr_count", count_buf, NULL) < 0' in qr_save_fn and
        "wapp->dpp->qr_code_num = (u8)next_count;" in qr_save_fn,
        "DPP QR save path lacks input/count bounds or checked persistence")


main_dpp_fn = extract_c_function(src["main"], "int dpp_read_config_file_for_connection(")
null_guard_return = main_dpp_fn.find("return WAPP_INVALID_ARG;")
null_guard_close = main_dpp_fn.find("}", null_guard_return)
dev_list_init = main_dpp_fn.find("dev_list = &wapp->dev_list;")
dev_list_use = main_dpp_fn.find("dl_list_for_each_safe(wdev, wdev_temp, dev_list")
require(null_guard_return >= 0 and null_guard_close > null_guard_return and
        dev_list_init > null_guard_close and dev_list_use > dev_list_init,
        "MAP R3 dev_list is not initialized after the wapp NULL guard")
require("u16 cred_len = 0;" not in main_dpp_fn,
        "DPP unused cred_len declaration remains in live MAP_R3_RECONFIG code")
require('wapp->dpp->qr_code_num = atoi(value)' not in main_dpp_fn and
        "dpp_read_qr_count(wapp, &qr_count) < 0" in main_dpp_fn and
        "wapp->dpp->qr_code_num = (u8)qr_count;" in main_dpp_fn,
        "main DPP config loader bypasses the bounded QR count parser")

print("PASS: DPP main config guards, parser bounds, QR count 0..100 validation, QR load/save/reset/remove error paths, OpenSSL 3 accessor and secret redaction")
