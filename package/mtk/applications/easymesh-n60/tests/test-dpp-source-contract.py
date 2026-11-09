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
    "dpp_reconfig": root / "wappd/dpp/dpp_reconfig.c",
    "dpp_wired": root / "wappd/dpp/dpp_wired.c",
    "dpp_debug": root / "wappd/dpp/dpp_debug.h",
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

# The main config loader must not rebuild a second, unused 1905 credential.
# Authentication-owned Connector/C-Sign/NetAccessKey buffers are packed and sent
# by the live wapp_dpp_process_config() path below, not by this config parser.
for dead_token in (
    "struct dpp_authentication auth;",
    "os_memset(&auth, 0, sizeof(auth));",
    '"_1905netAccessKey"',
    '"_1905cSignKey"',
    "wapp_dpp_save_dpp_cred(&auth)",
):
    require(dead_token not in parser,
            f"main DPP config loader retains the removed duplicate credential path: {dead_token}")


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


def extract_c_function(source, signature, occurrence=0):
    # Skip forward declarations: the first opening brace after a prototype may
    # belong to an unrelated function. Select only signatures whose next
    # declaration terminator is an opening brace, not a semicolon.
    starts = []
    cursor = 0
    while True:
        start = source.find(signature, cursor)
        if start < 0:
            break
        brace = source.find("{", start)
        semicolon = source.find(";", start)
        if brace >= 0 and (semicolon < 0 or brace < semicolon):
            starts.append(start)
            cursor = brace + 1
        else:
            cursor = start + len(signature)
    require(occurrence < len(starts),
            f"missing C function definition #{occurrence + 1}: {signature}")
    start = starts[occurrence]
    brace = source.find("{", start)
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


cred_fn = extract_c_function(src["dpp_wdev"], "struct dpp_sec_cred * wapp_dpp_save_dpp_cred(")
for token in ("if (!auth || !auth->connector || !auth->connector[0] ||",
              "!auth->c_sign_key || !auth->net_access_key)",
              "size_t connector_len, csign_len, net_access_key_len, payload_len;",
              "wpabuf_len(auth->c_sign_key)", "wpabuf_len(auth->net_access_key)",
              "!csign_key || !net_access_key", "connector_len > 0xffffU",
              "payload_len > 0xffffU - sizeof(*sec_cred)",
              "os_zalloc(sizeof(*sec_cred) + payload_len)",
              "sec_cred->payload_len = (unsigned short)payload_len",
              "os_memcpy(pos, auth->connector, connector_len)",
              "os_memcpy(pos, csign_key, csign_len)",
              "os_memcpy(pos, net_access_key, net_access_key_len)"):
    require(token in cred_fn, f"DPP packed credential builder lacks invariant: {token}")
require("cred_buffer" not in cred_fn and "unsigned short cred_len" not in cred_fn,
        "DPP packed credential builder retains the temporary copy or narrow accumulator")

process_sig = "static int wapp_dpp_process_config("
process_one = extract_c_function(src["dpp_wdev"], process_sig, occurrence=0)
process_two = extract_c_function(src["dpp_wdev"], process_sig, occurrence=1)
for idx, process_fn in enumerate((process_one, process_two), 1):
    require("wapp_dpp_save_dpp_cred(auth)" in process_fn and
            "wapp_send_1905_msg(wapp, WAPP_SEND_1905_CONNECTOR" in process_fn,
            f"DPP credential sender {idx} no longer uses the packed credential contract")
    wipe = process_fn.find("forced_memzero(cred, cred_len);")
    free = process_fn.find("os_free(cred);", wipe)
    require(wipe >= 0 and free > wipe,
            f"DPP credential sender {idx} frees credential material without clearing it")
    require("hex_dump_dbg" not in process_fn and "wpa_hexdump" not in process_fn,
            f"DPP credential sender {idx} logs credential material")
for idx, process_fn in enumerate((process_one, process_two), 1):
    require(re.search(r"\bu16\s+cred_len(?:\s*=\s*0)?\s*;", process_fn) is not None,
            f"DPP 1905 credential sender {idx} length is not explicitly declared or initialized")

for secret_dump in (
    'wpa_hexdump_ascii(MSG_DEBUG, DPP_MAP_PREX "DPP: first connector"',
    'wpa_hexdump_ascii(MSG_DEBUG, DPP_MAP_PREX "DPP: second connector"',
    'wpa_hexdump(MSG_DEBUG, DPP_MAP_PREX "in process config cign key"',
    'wpa_hexdump_ascii(MSG_DEBUG, DPP_MAP_PREX "in process config connector"',
    'hex_dump_dbg("save 1905 connector"',
    'hex_dump_dbg(DPP_MAP_PREX"dpp frame ',
    'wpa_hexdump(MSG_MSGDUMP, DPP_MAP_PREX "DPP: Received message attributes"',
    'wpa_hexdump_buf(MSG_DEBUG, "DPP: Configuration Response adv_proto"'):
    require(secret_dump not in src["dpp_wdev"],
            f"DPP credential or protocol payload dump remains: {secret_dump}")
require('hex_dump(DPP_MAP_PREX"Reboot BSS_connectors=' not in src["main"],
        "disabled BSS credential payload dump remains in main source")
require("wpabuf_clear_free(wapp->dpp_ctrlconnector);" in src["dpp_wdev"] and
        "wpabuf_free(wapp->dpp_ctrlconnector);" not in src["dpp_wdev"],
        "retained DPP connector is not cleared on replacement")
require("forced_memzero(wapp->dpp_csign, wapp->dpp_csign_len);" in src["dpp_wdev"],
        "retained DPP C-sign key is freed without clearing")

require("wapp_dpp_save_dpp_cred(" not in main_dpp_fn and
        "struct dpp_authentication auth;" not in main_dpp_fn and
        "struct dpp_sec_cred *cred" not in main_dpp_fn,
        "main DPP config loader retains a dead credential pack-and-free path")
for field in ("dpp_connector", "dpp_csign", "dpp_netaccesskey", "dpp_ppkey"):
    require(f"forced_memzero(config[k].{field}" in main_dpp_fn,
            f"temporary DPP {field} is not cleared before free")
require("forced_memzero(value, sizeof(value));" in main_dpp_fn and
        "forced_memzero(buf_temp, sizeof(buf_temp));" in main_dpp_fn,
        "DPP config parser leaves temporary key material on the stack")
require("forced_memzero(wdev->config->psk, sizeof(wdev->config->psk));" in main_dpp_fn,
        "DPP per-interface rollback leaves a copied PSK in memory")


bss_fn = extract_c_function(src["dpp_wdev"], "void wapp_snd_bss_conn_1905(")
for token in ("size_t group_id_len, msg1_len, msg2_len, payload_len;",
              "if (!wapp || !auth)", "if (!msg1 || !msg2)",
              "msg1_len > 0xffffU - msg2_len",
              "payload_len > 0xffffU - sizeof(*bss_cred)",
              "bss_cred->bh_connect_len = (unsigned short)msg1_len",
              "bss_cred->fh_connect_len = (unsigned short)msg2_len",
              "forced_memzero(bss_cred, cred_len)",
              "wpabuf_clear_free(msg1)", "wpabuf_clear_free(msg2)"):
    require(token in bss_fn, f"BSS connector packer lacks bound or cleanup invariant: {token}")
require("cred_buffer" not in bss_fn and "hex_dump_dbg" not in bss_fn and
        "wpa_hexdump" not in bss_fn,
        "BSS connector path retains temporary copy or raw credential logging")
bss_wipe = bss_fn.find("forced_memzero(bss_cred, cred_len);")
bss_free = bss_fn.find("os_free(bss_cred);", bss_wipe)
require(bss_wipe >= 0 and bss_free > bss_wipe,
        "BSS connector payload is freed without clearing")
clear_fn = extract_c_function(src["dpp_wdev"], "static void wapp_dpp_clear_cred(")
require("if (!auth)" in clear_fn and "forced_memzero(auth->ssid, SSID_MAX_LEN)" in clear_fn and
        "forced_memzero(auth->passphrase, 64)" in clear_fn,
        "DPP authentication SSID/passphrase cleanup is not NULL-safe and non-optimizable")
require("forced_memzero(wapp->dpp_csign, wapp->dpp_csign_len);" in src["main"],
        "main DPP configuration replaces a retained C-sign key without clearing")
require('wpa_hexdump(MSG_DEBUG, DPP_MAP_PREX "in process config cign key"' not in src["main"],
        "main DPP configuration still logs the C-sign key")


# DPP 018: all DPP translation units share one payload-redaction policy.
redaction_header = src["dpp_debug"]
require("#ifndef DPP_DEBUG_REDACT_H" in redaction_header and
        "#define DPP_REDACT_DUMP(level, title, data, data_len) do {" in redaction_header and
        'wpa_printf((level), "%s: [REDACTED]", (title));' in redaction_header,
        "shared DPP diagnostic redaction header is incomplete")
for macro in (
    "#define wpa_hexdump(level, title, buf, len) DPP_REDACT_DUMP(level, title, buf, len)",
    "#define wpa_hexdump_ascii(level, title, buf, len) DPP_REDACT_DUMP(level, title, buf, len)",
    "#define wpa_hexdump_buf(level, title, buf) DPP_REDACT_DUMP(level, title, buf, 0)",
    "#define wpa_hexdump_key(level, title, buf, len) DPP_REDACT_DUMP(level, title, buf, len)",
    "#define wpa_hexdump_buf_key(level, title, buf) DPP_REDACT_DUMP(level, title, buf, 0)",
):
    require(macro in redaction_header, f"shared DPP redaction policy omits {macro}")
for name in ("dpp", "dpp_reconfig", "dpp_wdev", "dpp_wired"):
    source = src[name]
    require(source.count('#include "dpp_debug.h"') == 1 and
            "DPP_REDACT_DUMP" not in source,
            f"{name}: shared DPP redaction header is not included exactly once")

key_debug = extract_c_function(src["dpp"], "void dpp_debug_print_key(")
require("dpp_debug_print_point(title, group, point)" in key_debug and
        "EVP_PKEY_print_private" not in key_debug and
        "i2d_ECPrivateKey" not in key_debug,
        "DPP key diagnostics must expose public EC points only")

for name, forbidden in (
    ("dpp", (
        'DPP_EVENT_CONNECTOR "After: %s"',
        'DPP_EVENT_C_SIGN_KEY "%s"',
        'DPP_EVENT_NET_ACCESS_KEY "%s"',
        'DPP: dppCon: %s',
        'DPP: Set configurator parameters: %s',
    )),
    ("dpp_reconfig", ('DPP: dppCon: %s', 'DPP: signedConnector: %s')),
    ("dpp_wdev", (
        'DPP_EVENT_CONNECTOR "%s"',
        'DPP_EVENT_CONFOBJ_PASS "%s"',
        'DPP_EVENT_CONFOBJ_PSK "%s"',
        'DPP_EVENT_C_SIGN_KEY "%s"',
        'DPP_EVENT_NET_ACCESS_KEY "%s"',
        'DPP_EVENT_PP_KEY "%s"',
    )),
    ("map", ('DPP: configurationObject JSON', 'DPP: 2nd configurationObject JSON')),
):
    for marker in forbidden:
        require(marker not in src[name],
                f"{name}: credential-bearing text log remains: {marker}")

for marker in ("_passphrase %s", "_PMK %s", "_PTK %s"):
    require(marker not in src["wdev"],
            f"DPP test helper still persists credential material: {marker}")

# Config ownership cleanup must cover replacement and allocation-failure paths.
cred_fn = extract_c_function(src["wdev"], "int wdev_set_dpp_cred(")
for token in (
    "forced_memzero(wdev->config->dpp_connector, os_strlen(wdev->config->dpp_connector) + 1)",
    "forced_memzero(wdev->config->dpp_netaccesskey, wdev->config->dpp_netaccesskey_len)",
    "forced_memzero(wdev->config->dpp_csign, wdev->config->dpp_csign_len)",
    "forced_memzero(wdev->config->dpp_ppkey, wdev->config->dpp_ppkey_len)",
    "forced_memzero(wdev->config->psk, sizeof(wdev->config->psk))",
    "forced_memzero(wdev->config2->dpp_connector, os_strlen(wdev->config2->dpp_connector) + 1)",
    "forced_memzero(wdev->config2->dpp_netaccesskey, wdev->config2->dpp_netaccesskey_len)",
    "forced_memzero(wdev->config2->dpp_csign, wdev->config2->dpp_csign_len)",
    "forced_memzero(wdev->config2->dpp_ppkey, wdev->config2->dpp_ppkey_len)",
    "forced_memzero(wdev->config2->psk, sizeof(wdev->config2->psk))",
    "forced_memzero(wdev_config->dpp_connector, os_strlen(wdev_config->dpp_connector) + 1)",
    "forced_memzero(wdev_config->dpp_csign, wdev_config->dpp_csign_len)",
    "forced_memzero(wdev_config->dpp_netaccesskey, wdev_config->dpp_netaccesskey_len)",
    "forced_memzero(wdev_config->dpp_ppkey, wdev_config->dpp_ppkey_len)",
    "forced_memzero(wdev_config->psk, sizeof(wdev_config->psk))",
):
    require(token in cred_fn, f"DPP config owner cleanup invariant missing: {token}")

psk_clear = main.find("forced_memzero(wdev->config->psk, sizeof(wdev->config->psk));")
psk_replace = main.find("os_memcpy(wdev->config, (char *)(&config[k])")
require(psk_clear >= 0 and psk_replace > psk_clear,
        "old per-interface PSK must be cleared before config replacement")
csign_transaction_markers = {
    "transaction flag declaration": re.search(
        r"\bint\s+dpp_csign_updated\s*=\s*0\s*;", main) is not None,
    "transaction flag update": re.search(
        r"\bdpp_csign_updated\s*=\s*1\s*;", main) is not None,
    "conditional global-key rollback": re.search(
        r"if\s*\(\s*dpp_csign_updated\s*&&\s*wapp->dpp_csign\s*\)", main) is not None,
}
missing_csign_markers = [name for name, present in csign_transaction_markers.items()
                         if not present]
if missing_csign_markers:
    csign_evidence = [
        line.strip() for line in main.splitlines()
        if "dpp_csign_updated" in line or "wapp->dpp_csign" in line
    ]
else:
    csign_evidence = []
require(not missing_csign_markers,
        "global C-sign transaction rollback invariant missing "
        f"{missing_csign_markers}; source matches={csign_evidence}")

error_label = main.rfind("\nerror:")
rollback_pos = main.find("if (dpp_csign_updated && wapp->dpp_csign)", error_label)
parser_cleanup_pos = main.find("if (config[k].dpp_connector)", error_label)
require(error_label >= 0 and rollback_pos > error_label and
        parser_cleanup_pos > rollback_pos,
        "transaction-owned global C-sign rollback must run at the common error exit")

config_loader = extract_c_function(main, "int dpp_read_config_file_for_connection(")
for token in (
    "forced_memzero(config[k].dpp_connector, os_strlen(config[k].dpp_connector) + 1)",
    "forced_memzero(config[k].dpp_csign, config[k].dpp_csign_len)",
    "forced_memzero(config[k].dpp_netaccesskey, config[k].dpp_netaccesskey_len)",
    "forced_memzero(config[k].dpp_ppkey, config[k].dpp_ppkey_len)",
):
    require(token in config_loader,
            f"successful DPP config load must clear temporary credential ownership: {token}")
success_return = config_loader.find("return WAPP_SUCCESS;")
temp_connector_clear = config_loader.find("forced_memzero(config[k].dpp_connector")
require(temp_connector_clear >= 0 and success_return > temp_connector_clear,
        "temporary Connector must be cleared and freed before successful config return")
for token in (
    "os_free(config[k].dpp_connector)",
    "os_free(config[k].dpp_csign)",
    "os_free(config[k].dpp_netaccesskey)",
    "os_free(config[k].dpp_ppkey)",
    "os_free(config[k].ssid)",
):
    require(token in config_loader,
            f"successful DPP config load must release temporary owner: {token}")

success_qr_start = config_loader.find("if (wapp->dpp) {")
success_cleanup_start = config_loader.rfind("if (config[k].dpp_csign)", 0, success_qr_start)
require(success_cleanup_start >= 0 and success_qr_start > success_cleanup_start,
        "DPP parser success cleanup is not located before QR-count validation")
success_cleanup = config_loader[success_cleanup_start:success_qr_start]
for field in ("dpp_connector", "dpp_csign", "dpp_netaccesskey", "dpp_ppkey", "ssid"):
    require(success_cleanup.count(f"os_free(config[k].{field})") == 1,
            f"temporary DPP {field} must have exactly one success-path free")





# The active OpenWrt WAPP build disables DPP_R2_MUOBJ. Its saved-config
# restore path must decode hexadecimal credentials as bytes, fail closed,
# and release every temporary auth-owned credential on every exit.
wapp_make = (root / "wappd" / "Makefile").read_text(encoding="utf-8")
require("#CFLAGS += -DDPP_R2_MUOBJ" in wapp_make and
        re.search(r"(?m)^CFLAGS\s*\+=\s*-DDPP_R2_MUOBJ\b", wapp_make) is None,
        "the audited active WAPP profile is no longer the non-MUOBJ DPP path")
fetch_saved_dpp = extract_c_function(
    src["dpp_wdev"], "static int dpp_fetch_dpp_akm_param(")
require(fetch_saved_dpp.count("hex_len > sizeof(buftemp) * 2") == 2 and
        fetch_saved_dpp.count("hexstr2bin(buf, buftemp, key_len) < 0") == 2,
        "saved DPP NetAccessKey/C-Sign hex parsing lacks even-length and byte-capacity checks")
require(fetch_saved_dpp.count("wpabuf_alloc(key_len)") == 2 and
        fetch_saved_dpp.count("wpabuf_put_data(") == 2 and
        "auth->net_access_key->used" not in fetch_saved_dpp and
        "auth->c_sign_key->used" not in fetch_saved_dpp,
        "saved DPP key buffers are not populated using decoded byte lengths")
require(fetch_saved_dpp.count("if (!buf || !buf[0])") == 3 and
        fetch_saved_dpp.count("NdisZeroMemory(ifparam, sizeof(ifparam))") == 3 and
        fetch_saved_dpp.count("os_snprintf_error(sizeof(ifparam), ret)") == 3,
        "saved DPP restore accepts empty fields or lacks bounded interface-key formatting")
require("hexstr2bin(buf, buftemp, os_strlen(buf))" not in fetch_saved_dpp and
        "return -1;" in fetch_saved_dpp and
        "forced_memzero(buftemp, sizeof(buftemp));" in fetch_saved_dpp,
        "saved DPP parser retains the hex-length overrun or lacks fail cleanup")
system_fail = fetch_saved_dpp.find("if (ret != 0) {")
require(system_fail >= 0 and fetch_saved_dpp.find("goto fail;", system_fail) > system_fail,
        "saved DPP restore continues after DPP-enable command failure")
saved_conf_init = extract_c_function(src["dpp_wdev"], "void dpp_conf_init(", occurrence=1)
require("if (dpp_fetch_dpp_akm_param(wdev, auth, dat_ctx) < 0)" in saved_conf_init and
        "goto out;" in saved_conf_init,
        "DPP saved-config restore continues after a credential parse/allocation failure")
for token in ("forced_memzero(auth->connector, os_strlen(auth->connector) + 1);",
              "wpabuf_clear_free(auth->net_access_key);",
              "wpabuf_clear_free(auth->c_sign_key);",
              "forced_memzero(auth, sizeof(*auth));",
              "os_free_mem(NULL, auth);"):
    require(token in saved_conf_init,
            f"temporary DPP auth cleanup is missing: {token}")
require(saved_conf_init.find("forced_memzero(auth, sizeof(*auth));") <
        saved_conf_init.find("os_free_mem(NULL, auth);"),
        "temporary DPP auth object is freed before its inline credential state is cleared")

for occurrence in (0, 1):
    deinit_fn = extract_c_function(src["dpp"], "void dpp_auth_deinit(", occurrence=occurrence)
    for token in ("wpabuf_clear_free(auth->net_access_key);",
                  "wpabuf_clear_free(auth->c_sign_key);",
                  "wpabuf_clear_free(auth->pp_key);"):
        require(token in deinit_fn,
                f"DPP auth deinit variant {occurrence + 1} does not clear {token}")
default_deinit = extract_c_function(src["dpp"], "void dpp_auth_deinit(", occurrence=1)
require("forced_memzero(auth->connector, os_strlen(auth->connector) + 1);" in default_deinit,
        "DPP auth deinit frees the signed Connector without clearing it")
for signature, token in (
    ("static void dpp_copy_csign(", "wpabuf_clear_free(auth->c_sign_key);"),
    ("static void dpp_copy_ppkey(", "wpabuf_clear_free(auth->pp_key);"),
    ("static void dpp_copy_netaccesskey(", "wpabuf_clear_free(auth->net_access_key);"),
):
    copy_fn = extract_c_function(src["dpp"], signature)
    require(token in copy_fn, f"DPP key replacement does not clear old material: {signature}")


# Hex restoration regression vectors: decoded capacity is bytes, not hex characters.
require(fetch_saved_dpp.count("if (!hex_len || (hex_len & 1) || hex_len > sizeof(buftemp) * 2)") == 2,
        "both saved DPP key parsers must reject empty, odd-length and over-capacity hex")
def dpp_hex_decoded_length(value):
    if (not value or len(value) % 2 or len(value) // 2 > 512 or
            re.fullmatch(r"[0-9a-fA-F]+", value) is None):
        return None
    return len(value) // 2

for raw, expected in (
    ("00", 1),
    ("0123456789abcdef", 8),
    ("ab" * 512, 512),
):
    require(dpp_hex_decoded_length(raw) == expected,
            f"DPP hex restore decoded-byte boundary is wrong for {len(raw)} hex chars")
for raw in ("", "0", "0g", "ab" * 513, " 0"):
    require(dpp_hex_decoded_length(raw) is None,
            f"DPP hex restore accepted invalid/oversized input: {raw[:16]!r}")


print("PASS: DPP saved-config bounds, fail-closed rollback, auth cleanup and log redaction")
