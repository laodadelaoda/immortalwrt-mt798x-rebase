# WAPP 7.6.7.3 / WTS / EasyMesh ABI audit

Audit date: 2026-10-31  
Target branch: `n60pro-mtk-closed-driver`  
WAPP source archive: `wappd-80ca5724.tar.bz2`  
Archive SHA-256: `73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462`

The source archive was downloaded by GitHub Actions, SHA-256 verified, and extracted. The source audit workflow is `.github/workflows/wapp-source-audit.yml`.

## 1. WTS parser: `wapp_read_wts_map_config()`

Source: `wappd/common/main.c`, function beginning at line 258.

The parser accepts records with this token order:

```text
<index>,<mac> <opclass> <ssid> <authmode> <encryptype> <key> <resv1> <resv2> [hidden-<Y|N> ...]
```

- The record index ends at the first comma.
- MAC is six colon-separated hexadecimal octets.
- Operating class prefixes map as: `8x` -> 2.4 GHz, `11x` -> 5 GHz low, `12x` -> 5 GHz high; `13x` is recognized only when `MAP_6E_SUPPORT` is compiled.
- Auth mode and encryption type are parsed as hexadecimal values with a `0x` prefix.
- SSID and key are whitespace-delimited. A backslash-space sequence represents a literal SSID space; a doubled backslash represents a literal backslash. The parser converts escaped spaces to SUB (0x1a) during tokenization and restores them afterward.
- `resv1 & 1` maps to the BH BSS flag (bit 6); `resv2 & 1` maps to the FH BSS flag (bit 5).
- If a `hidden-` token exists, its following character controls hidden SSID (`Y` or `N`). If absent, hidden SSID defaults to `N`.
- Trailing text after the hidden token is not interpreted by this WAPP parser; other daemons may still consume those trailing WTS fields.
- The parser returns the number of records through `config_bss_num`; it can return success with zero records. The empty `#ucc_bss_info` template therefore parses as zero BSS entries, not as a usable configuration.

Capacity is `WTS_FILE_READ_LINE * max_bss_num`, with `WTS_FILE_READ_LINE=100`. `MAX_SET_BSS_INFO_NUM` is 58 without `MAP_6E_SUPPORT`, or 99 with it. The parser also emits warnings when 2.4 GHz, 5 GHz low, or 5 GHz high operating classes are absent; those warnings are not equivalent to a parse failure.

### Parser robustness defects observed upstream

- `%s` is used without field widths for `op_class[4]`, `ssid[33]`, and `key[65]`.
- Most `sscanf` results are checked only against `EOF`, not against the expected conversion count; malformed fields can therefore be accepted.
- Several parse variables are reused between records rather than reset for each record.
- Unknown operating-class prefixes are not rejected explicitly.
- The parser's success return does not require any BSS record.

These are findings in the supplied vendor source. The repository currently packages a prebuilt WAPP binary, so changing the C source alone would not change the installed binary.

## 2. WTS generation and update paths

A full automatic WTS generator from local UCI/driver BSS state at daemon startup was **not found** in this source archive.

Two update paths were found:

1. **Controller-provided configuration:** `wappd/dpp_config_agent_impl.lua:533`, `DevSetConfigMediatek(cmd)`, truncates and rebuilds `/etc/map/wts_bss_info_config` from incoming `dev_set_config,bss_info1...` fields, then invokes `1905ctrl controller dev_set_config <file>`. Its caller handles incoming `dev_set_config,` messages. This is a provisioning path driven by received configuration, not local startup discovery.
2. **WPS configuration event:** `wappd/common/wapp_cmm.c` dispatches `WAPP_CONFIG_WPS_EVENT` to `wdev_wps_configuration_handle()` in `wappd/common/wdev.c`. The handler is compiled under `WPS_UNCONFIG_FEATURE_SUPPORT` (enabled by this source Makefile). It updates an existing WTS record using WPS event SSID/key/auth/encryption/channel/index, writes the file, then sends `WAPP_MAP_RENEW` to MAPD.

The WPS update path is not a general generator: it requires the target record and its next sequential index to exist, only handles the 2.4 GHz / 5 GHz low / 5 GHz high classes, and rewrites the file in place. It cannot safely bootstrap the current empty template.

The WAPP reader and `WAPP_USER_GET_WTS_CONFIG` handler only read and serialize the current file; they do not generate it.

## 3. WAPP event and client registration

- WAPP opens a Unix datagram server at `/tmp/wapp_server` in `wapp_iface_init()`.
- Clients attach through the WAPP user-interface attach path; the peer socket address and daemon name are stored in the client list.
- `SET_REGITER_EVENT` (command type 0x01) accepts a 16-bit event ID and sets the corresponding bit in a 256-event registration bitmap.
- User commands in the `WAPP_USER_MIN_CMD < type < WAPP_USER_MAX_CMD` range are dispatched to `map_handler()`.
- `send_event_dispatch()` sends events to an explicitly named daemon, to clients that registered the event ID, or to a client with a matching pending asynchronous command.
- The driver event path reaches `wapp_event_handle()`; `WAPP_CONFIG_WPS_EVENT` is the WPS-to-WTS update trigger.
- The separate WAPP control socket supports `EVENT_REGISTER` / `EVENT_UNREGISTER`; this is not the same wire message as the binary WAPP user-command/event protocol.

## 4. WAPP / MAPD / P1905 compatibility evidence

The packaged `wapp`, `mapd`, and `p1905_managerd` are all AArch64 ELF executables using the musl dynamic loader. Their strings show the expected WAPP Unix socket path and attach/detach protocol. MAPD contains the message `wts_bss_info_config file has been updated. do renew procedure`. P1905 contains `/etc/map/wts_bss_info_config` and the failure message `read wts_bss_info_config fail or no valid bss info`.

The WAPP source defines a packed `set_config_bss_info` structure containing MAC, operating class, SSID, auth mode, encryption type, key, BH/FH flags, hidden flag and local radio/use fields. The WAPP `WAPP_WTS_CONFIG` event copies a fixed `MAX_SET_BSS_INFO_NUM * sizeof(struct set_config_bss_info)` payload. This is an ABI-sensitive fixed-layout message.

**Compatibility conclusion:** socket naming, attach/detach strings, WAPP event vocabulary, and MAPD's WTS-renew behavior are consistent with this WAPP implementation. However, the packaged MAPD and P1905 binaries are stripped and do not expose enough build metadata or structure symbols to prove exact compile-time ABI identity (including whether their BSS array was compiled with the same `MAP_6E_SUPPORT` capacity). Do not claim full ABI verification until their build provenance or matching headers are confirmed.

## 5. Consequence for this N60 build

The current repository template contains only `#ucc_bss_info`. The P1905 binary explicitly reports failure when the WTS file is absent or contains no valid BSS information. The current startup script passes that empty template directly to `p1905_managerd`; it does not create WTS first.

Therefore the existing CI preflight rejection is correct and must not be weakened merely to make the firmware build green. The remaining implementation blocker is a tested runtime generator that reads the live wireless configuration/driver state, produces the exact WTS record semantics required by both P1905 and WAPP, validates it, and atomically installs it before P1905 starts. The auth-mode/encryption numeric mapping and all trailing WTS fields must be established from matching vendor code or verified runtime data, not guessed.
