# WAPP 7.6.7.3 / WTS / EasyMesh ABI audit

Audit date: 2026-10-31  
Target branch: `n60pro-mtk-closed-driver`  
Release tag: `dl-sources-7.6.7.3`

## 1. Audited source archives

| Component | Release asset | SHA-256 |
|---|---|---|
| WAPP | `wappd-80ca5724.tar.bz2` | `73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462` |
| MAPD | `mapd-6eca4331.tar.bz2` | `39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18` |
| P1905 | `1905daemon-35234223.tar.bz2` | `82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795` |
| MTK driver | `mt79xx_20250408-705eb4.tar.xz` | `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78` |

The WAPP archive was downloaded and SHA-256 verified by the GitHub Actions source-audit workflow. The MAPD, P1905 and driver archives were also extracted and inspected for this audit. The audit workflow is `.github/workflows/wapp-source-audit.yml`.

## 2. WTS parser: `wapp_read_wts_map_config()`

Source: `wappd/common/main.c`, function beginning at line 258.

The parser accepts records with this token order:

```text
<index>,<mac> <opclass> <ssid> <authmode> <encryptype> <key> <resv1> <resv2> [hidden-<Y|N> ...]
```

- The record index ends at the first comma. WAPP parses it but does not store it in `set_config_bss_info`; records are copied into the array in file order.
- MAC is six colon-separated hexadecimal octets.
- Operating-class prefixes map as: `8x` -> 2.4 GHz, `11x` -> 5 GHz low, `12x` -> 5 GHz high; `13x` is recognized only when `MAP_6E_SUPPORT` is compiled.
- Auth mode and encryption type are hexadecimal WPS bitfields. The source defines WPA2-PSK as `0x0020`, SAE as `0x0040`, and AES as `0x0008`.
- SSID and key are whitespace-delimited. A backslash-space sequence represents a literal space; a doubled backslash represents a literal backslash. The parser converts escaped spaces to SUB (0x1a) during tokenization and restores them in the SSID/key.
- `resv1 & 1` maps to the BH BSS flag (bit 6); `resv2 & 1` maps to the FH BSS flag (bit 5).
- If a `hidden-` token exists, its following character controls hidden SSID (`Y` or `N`). If absent, hidden SSID defaults to `N`.
- Trailing VLAN/PVID/PCP fields are not interpreted by this WAPP parser. P1905 parses the same text file independently and does consume trailing VLAN fields.

Capacity is `WTS_FILE_READ_LINE * max_bss_num`, with `WTS_FILE_READ_LINE=100`. `MAX_SET_BSS_INFO_NUM` is 58 without `MAP_6E_SUPPORT`, or 99 with it. The parser emits warnings when operating-class groups are absent, but those warnings are not equivalent to a parse failure.

### Parser robustness defects observed upstream

- `%s` is used without field widths for `op_class[4]`, `ssid[33]`, and `key[65]`.
- Most `sscanf` results are checked only against `EOF`, not against the expected conversion count; malformed fields can therefore be accepted.
- Several parse variables are reused between records rather than reset for each record.
- Unknown operating-class prefixes are not rejected explicitly.
- The parser can return success with zero records.
- If the WTS file cannot be opened, the parser returns before zeroing the caller's output array.

These are findings in the supplied vendor source. The repository packages a prebuilt WAPP binary, so changing the C source alone would not change the installed binary.

## 3. WAPP WTS read path and MAPD boot trigger

The MAPD controller boot path is:

1. `topo_srv_init_own_info()` sets `need_to_update_wts = 1`.
2. MAPD queries operational BSS information for each discovered radio with `WAPP_USER_GET_OPERATIONAL_BSS`.
3. The resulting `WAPP_OPERBSS_REPORT` is handled by `wlanif_handle_oper_bss_report()`.
4. Only when `device_role == DEVICE_ROLE_CONTROLLER` and `need_to_update_wts` is still set does MAPD call `topo_srv_update_wts_config()`.
5. That function issues `WAPP_USER_GET_WTS_CONFIG` and waits for `WAPP_WTS_CONFIG`.
6. WAPP's `map_handler()` dispatches the command to `map_handle_get_wts_config()`, which calls `wapp_read_wts_map_config()` and serializes a fixed-size BSS array.
7. MAPD's `topo_srv_parse_wts_config()` clears its array, copies the returned payload, and sets `need_to_update_wts = 0`.

This is a read-and-transfer path, not a WTS generator. The request is controller-only and is normally initiated by the first operational-BSS report after MAPD initialization.

### Empty/missing WTS behavior is unsafe

- With the current empty `#ucc_bss_info` template, WAPP opens the file, zeroes the output array, returns a record count of zero, and still serializes the full fixed-size array.
- `map_handle_get_wts_config()` ignores both the parser return value and `config_bss_num`.
- MAPD copies the payload and clears `need_to_update_wts` without checking that any BSS record exists. It therefore treats an empty WTS as synchronized and does not retry until a later renew.
- If the file is missing, WAPP returns before zeroing the stack array; the caller ignores the error and can serialize uninitialized stack contents.
- MAPD's `topo_srv_parse_wts_config()` copies `config_length` without checking it against the destination array size. A WAPP/MAPD capacity mismatch could therefore overflow the MAPD buffer.

## 4. WTS update triggers: exact conditions

### 4.1 WPS configuration event

The driver source shows this is not a generic UCI-change notification.

1. `WscUpdatePortCfgTimeout()` compares the incoming WPS credential with the active BSS: AKM/auth mode, pairwise cipher, SSID and PSK.
2. If all are unchanged, it returns without sending a WAPP event.
3. If the configuration changed, it calls `WscWriteConfToPortCfg()`.
4. Under `CONFIG_MAP_SUPPORT && WPS_UNCONFIG_FEATURE_SUPPORT`, the driver calls `wapp_send_wps_config()`.
5. The driver sends `WAPP_CONFIG_WPS_EVENT` through the WEXT custom event `OID_WAPP_EVENT`.
6. WAPP's `wapp_event_handle()` dispatches `WAPP_CONFIG_WPS_EVENT` to `wdev_wps_configuration_handle()`.
7. The handler reads the existing WTS file, replaces one existing indexed record, writes the file, and sends `WAPP_MAP_RENEW`.
8. MAPD receives the registered `WAPP_MAP_RENEW` event; `wlanif_handle_mapd_renew()` calls `mapd_renew()`.
9. `mapd_renew()` sets `need_to_update_wts = 1`, requests WAPP radio renewal, and calls `map_1905_Set_Read_Bss_Conf_and_Renew_v2()`. The next operational-BSS report can trigger another WTS read.

The WAPP and driver Makefiles define `WPS_UNCONFIG_FEATURE_SUPPORT` for the MAP path, so this is a real compiled source path when MAP support is enabled.

### 4.2 Limitations of the WPS writer

The WPS handler is a record updater, not a bootstrap generator:

- It requires the target index and the next sequential index to exist. It cannot create the initial WTS file or safely update the final record.
- It always marks the first record in a band as BH and later records as FH; it logs the incoming `bss_role` but does not use it to preserve the existing role.
- It writes `hidden-N` and vendor-specific VLAN/PVID text rather than deriving those fields from the live wireless configuration.
- It writes the file in place with `fopen(..., "w+")`; there is no temporary file plus atomic rename.
- It does not escape SSID/key spaces or backslashes before writing.
- Its 5 GHz high-band branch requires both `radio_num >= 3` and a high channel. N60 has two radios, so a 5 GHz channel >=100 can be written as `11x` rather than `12x`.
- It handles `8x`, `11x`, and `12x`; it has no corresponding `13x` update branch.

Do not use this upstream writer as the generic runtime generator.

### 4.3 DPP/UCC provisioning path

The source archive also contains `dpp_config_agent_impl.lua`, whose `DevSetConfigMediatek(cmd)` path truncates and rebuilds WTS from incoming `dev_set_config,bss_info...` fields. This is externally supplied provisioning data, not local startup discovery. The current WAPP package install rules and the current `easymesh-n60` package do not install that Lua agent, so it is not an active initial-WTS mechanism in the current N60 package.

WAPP's DPP configurator startup path can read WTS when DPP configurator support is enabled; that path also reads existing WTS and does not generate it.

## 5. WAPP interface registration and event transport

- `wapp_get_wireless_interfaces()` reads `bss_config_priority` from MAP configuration. If non-empty, it treats the value as a static semicolon-separated interface list, validates each name with `SIOCGIWNAME`, obtains its MAC and creates a WAPP device. Only when the list is empty does it scan `/proc/net/dev` dynamically.
- WAPP receives `/etc/map/mapd_cfg` via `-F`, where N60 fixes `bss_config_priority=ra0;rax0`. The separate P1905 `/etc/map/1905d.cfg` retains `bss_config_priority=ra0;rax0;apclix0`; these are distinct consumers and their lists must not be treated as interchangeable.
- WAPP's binary user-interface server binds `/tmp/wapp_server`. MAPD's `wapp_usr_intf_ctrl_open("mapd", ...)` client binds an abstract-namespace local socket, connects to `/tmp/wapp_server`, and sends `ATTACH:mapd`.
- MAPD registers event IDs with the binary `SET_REGITER_EVENT` command (type `0x01`). WAPP stores the event IDs in the client's registration bitmap; `send_event_dispatch()` uses that bitmap to deliver asynchronous events.
- MAPD's event list includes `WAPP_MAP_RENEW`. `WAPP_WTS_CONFIG` is not an unsolicited registered event; it is the synchronous response to `WAPP_USER_GET_WTS_CONFIG`.
- The WAPP filesystem control socket `/tmp/wapp_ctrl` handles text CLI commands such as `EVENT_REGISTER` / `EVENT_UNREGISTER`. It is distinct from MAPD's abstract local socket name and the binary `/tmp/wapp_server` protocol.

## 6. WAPP / MAPD / P1905 ABI compatibility

### WAPP <-> MAPD

The source definitions of `struct GNU_PACKED set_config_bss_info` in WAPP `include/wapp_cmm.h` and MAPD `mapd_i.h` have identical field order and types:

```c
unsigned char mac[ETH_ALEN];
char oper_class[4];
char ssid[33];
unsigned short authmode;
unsigned short encryptype;
char key[65];
unsigned char wfa_vendor_extension;
unsigned char hidden_ssid;
unsigned char operating_chan;
unsigned char is_used;
```

The packed size is 116 bytes. The event/command enum positions also match in the two headers:

- `WAPP_WTS_CONFIG = 0x5A`
- `WAPP_USER_GET_WTS_CONFIG = 0xD4`

The array capacity is conditional in all three source components: 58 without `MAP_6E_SUPPORT`, 99 with it. The N60 config explicitly disables `CONFIG_MTK_MAP_R2_6E_SUPPORT`, so the intended build capacity is 58. The source Makefiles enable `MAP_6E_SUPPORT` only when that Kconfig option is selected.

**Source-level WAPP/MAPD ABI is therefore confirmed.** The remaining binary-level caveat is that the checked-in WAPP/MAPD executables are prebuilt and stripped; their exact compile-time `MAP_6E_SUPPORT` setting is not recorded. It must match, because MAPD copies the event's supplied length without a destination-size check.

### P1905 is a separate text-file consumer

P1905 does not receive the WAPP packed structure over this MAPD socket. Its `struct set_config_bss_info` is a separate, unpacked internal structure with additional fields such as `band_support`, `pvid`, `pcp`, `ssid_len`, and `vid`. P1905 independently parses the WTS text file. Therefore the P1905 structure must not be compared as if it were the WAPP/MAPD IPC payload.

P1905 loads WTS during initialization. An empty file can produce a zero-entry configuration without making the daemon's initial file-read call fail. The explicit `read_bss_conf_and_renew()` and `read_bss_conf_and_renew_v2()` paths reject `bss_config_num == 0`. The P1905 log string about "fail or no valid bss info" belongs to those configuration/renew paths; it does not prove that the daemon necessarily exits at initial startup.

## 7. Decision for the N60 repository

The current repository template contains only `#ucc_bss_info`. WAPP does not generate the initial local BSS profile set. Its normal path reads WTS; its WPS path only rewrites an existing record; the optional DPP/UCC Lua path requires externally supplied provisioning data and is not installed in this package.

Therefore:

1. Keep the fail-closed CI check. Do not allow an empty WTS template to pass merely to make the firmware build green.
2. Add a generic runtime WTS generator and validator, with MTK-specific radio/interface discovery isolated in an adapter. The generator must read live UCI/runtime state, not commit SSIDs, keys or BSSIDs.
3. Run generation and validation after wireless interfaces are ready but before WAPP's DPP configurator can read WTS and before P1905 starts.
4. Write to a temporary file, validate every record and required radio group, then atomically rename it into place. Any failure must block P1905/MAPD startup.
5. Fix or replace the upstream WPS writer behavior (or deliberately disable that path if WPS provisioning is not used); otherwise it can rewrite roles/opclasses and truncate the WTS file non-atomically.
6. Preserve matching WAPP/MAPD/P1905 compile-time MAP 6E settings. For N60, the target config has MAP 6E disabled.

The current CI preflight correctly rejects the missing runtime generator. The remaining implementation blocker is not the WAPP parser: it is the absence of a tested runtime generator/validator and the unsafe WPS record updater. Do not rerun the full firmware build until those files and synthetic tests are committed.
