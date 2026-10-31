# N60 Pro EasyMesh runtime validation

This document records the runtime contract for the N60 Pro MTK closed-driver
EasyMesh package. It deliberately distinguishes build-time capability checks
from proof that the live driver, WAPP, P1905 and MAPD have completed their
runtime event exchange.

## WTS source of truth

The N60 EasyMesh package restores the original vendor WTS test profile file
from the earlier N60 defaults. It contains 16 fixed records using the vendor
test SSIDs `Multi-AP-*` and test keys `maprocks1` through `maprocks4`.
These are intentional vendor test defaults, not the router's live SSID/PSK
credentials. The file is stored at
`/etc/map/wts_bss_info_config` and is passed unchanged to both WAPP and P1905.

The vendor profile set contains operating-class groups `8x`, `11x`, `12x`
and `13x`, including 6 GHz test entries. N60 Pro itself remains a dual-band
2.4/5 GHz device and has no 6 GHz PHY; restoring vendor defaults does not add
6 GHz hardware capability or change `radio_band=24G;5GL;5GH;` in
`1905d.cfg`. These extra records are retained because the requested baseline
is the original vendor EasyMesh test profile set, not a live-radio-derived
profile list.

There is deliberately **no runtime SSID/WTS generator**. Startup does not read
DAT files to synthesize WTS entries, does not overwrite vendor test SSIDs, and
does not copy the live router's PSK into the WTS file. The service checks that
the checked-in WTS file has the header and all 16 vendor records before
starting WAPP/P1905. CI compares the file against the exact expected vendor
default content.

The selected `mtwifi-cfg-ucode` backend continues to map the active
`wireless` UCI AP sections into the two local DAT profiles. Its source writes
`SSID1`, `WPAPSK1`, `AuthMode`, `EncrypType`, `HideSSID` and
`RRMEnable`, then calls `save_profile(dats, profile)` before bringing AP
VIFs up. This wireless configuration path is independent of the fixed vendor
WTS test profile file.

## Startup ordering and readiness gates

The init service now:

1. Waits for `ra0` and `rax0` to report AP mode and a non-empty SSID in
   three consecutive samples; interface-directory existence alone is not
   considered ready.
2. Validates the checked-in 16-record vendor WTS file; it does not generate
   SSIDs or rewrite WTS from DAT files.
3. Starts WAPP and requires both expected Unix sockets:
   - `/tmp/wapp_server` — WAPP event/server endpoint.
   - `/tmp/wapp_ctrl` — WAPP control endpoint used by `wappctrl`.
4. Uses `wappctrl ra0 drv_version` and `wappctrl rax0 drv_version` to verify
   that WAPP registered both driver interfaces.
5. Runs the vendor WAPP v3.0.2.0 `mbo reset_default` command on both radios
   after the control socket is ready. Failure is fatal to WAPP startup.
6. Starts P1905 only after both WAPP sockets and both interface checks succeed,
   passing the unchanged vendor WTS file through `-F`.
7. Starts MAPD after launching P1905, preserving the existing MAPD configuration and
   generated `/etc/mapd_strng.conf`. The current two-second delay is only a
   launch-order cushion, not proof that P1905 completed initialization; a
   source-verified P1905 ready signal remains outstanding.

A running PID without these sockets is not treated as a ready WAPP service.

## Build-time checks

GitHub Actions now:

- Compares `wts_bss_info_config` byte-for-byte with the original 16-record
  vendor EasyMesh test profile set.
- Checks that the init service, WAPP wrapper and package install rules do not
  reference a runtime WTS/SSID generator.
- Checks the shipped WAPP binary for event registration, WAPP sockets,
  802.11k RRM, 11v/WNM BTM and BTM request API symbols.
- Checks MAPD steering/topology state-machine symbols and P1905 WTS/topology
  discovery symbols.

These checks prove that the checked-in vendor WTS defaults are intact, that
runtime generation is not wired into startup, and that the binaries contain
the expected code paths. They do **not** prove that the live driver accepted
event registration, that a neighbor was discovered, or that a real client
received and acted on a BTM request.

## Runtime acceptance criteria

The router-side validation is complete only when all applicable observations
are present:

- WTS contains the original 16 vendor test profiles (`Multi-AP-*` and
  `maprocks1`–`maprocks4`) exactly as committed; no runtime SSID generator runs.
- Both WAPP sockets exist and remain present while WAPP runs.
- P1905 logs successful WTS parsing (16 vendor test records) and sends topology
  discovery; when an EasyMesh peer is connected, its neighbor/AL-MAC entry
  appears in topology state.
- MAPD creates `/tmp/mapd_ctrl` and receives topology/metrics events from
  P1905/WAPP.
- For 11k, both DAT files retain `RRMEnable=1`, and the driver/WAPP neighbor
  report path is exercised.
- For 11v, the runtime trace must show a MAPD steering decision, WAPP BTM
  request issuance, a BTM response/report, and the corresponding steering
  completion or failure. Receiving a BTM Query alone is not proof that BTM
  requests work.

The historical `hanwckf/immortalwrt-mt798x` PR #205 targeted OpenWrt
21.02/MAP R1 and started the separate `bs20` daemon. It also disabled MAP R2
and R3 before setting `mapEnable=2`. Those legacy settings are **not** copied:
this N60 Pro uses MAP R3, P1905 Controller/Root and MAPD's centralized
Steering FSM, so a separate `bs20` instance or disabling MAP R3 would be the
wrong control plane. The portable WAPP v3.0.2.0 MBO reset-default operation is
retained after driver-interface registration.

WAPP receives `/etc/map/mapd_cfg` through its `-F` option, so its deterministic
radio discovery list is `bss_config_priority=ra0;rax0` in that file. The
separate `1905d.cfg` retains its own existing `ra0;rax0;apclix0` list; the two
consumers must not be conflated.

The current configuration already enables `SteerEnable=1` and
`CentralizedSteering=1`; the workflow also requires
`CONFIG_MTK_MBO_SUPPORT=y`. No additional guessed WNM/BTM DAT key is added:
the exact BTM request/response path must be verified against the live
7.6.7.3 driver and WAPP logs.
