# N60 Pro EasyMesh runtime validation

This document records the runtime contract for the N60 Pro MTK closed-driver
EasyMesh package. It deliberately distinguishes build-time capability checks
from proof that the live driver, WAPP, P1905 and MAPD have completed their
runtime event exchange.

## WTS source of truth

The repository stores only the one-line `#ucc_bss_info` WTS template. It must
not contain real SSIDs, PSKs, factory test SSIDs, or static test BSS records.

At boot, `mtwifi-cfg` first maps the active `wireless` UCI AP sections into
the two local DAT profiles. Its source writes `SSID1`, `WPAPSK1`,
`AuthMode`, `EncrypType`, `HideSSID` and `RRMEnable`, then calls
`save_profile(dats, profile)` before bringing the AP VIFs up. The EasyMesh
service waits for both AP interfaces to report stable Master mode before it
reads those profiles. GitHub Actions checks these source-level contracts so
a future mtwifi-cfg change cannot silently break WTS input generation.

At boot, `generate-wts-bss-info` reads the router-local files:

- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat` (2.4 GHz)
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat` (5 GHz)

It requires the first active BSS values for `SSID1` (or `SSID`),
`AuthMode=WPA2PSK`, `RRMEnable=1`, `EncrypType=AES`, `WPAPSK1` (or
`WPAPSK`) and `HideSSID` (or `HideSSID1`). If `BssidNum` is present, it
must be 1. Unsupported security modes, missing values, disabled RRM, invalid
SSID/PSK syntax, or multiple BSS values fail closed; the service does not start
with a guessed profile.

The generated WTS contains three N60 Pro profiles:

| Index | Operating class | Source |
|---|---|---|
| 1 | `8x` | 2.4 GHz DAT |
| 2 | `11x` | 5 GHz DAT, low-band profile |
| 3 | `12x` | 5 GHz DAT, high-band profile |

The N60 Pro has no 6 GHz PHY, so no `13x` profile is emitted. The 5 GHz
radio can operate in either the low or high 5 GHz channel range; both WTS
operating-class profiles use the same live 5 GHz SSID/security settings.
The BSSID wildcard, WPA2-PSK/AES values, Backhaul/Fronthaul flags, hidden
marker and untagged VLAN tail follow the audited N60/vendor WTS record
layout. Before writing, the generator also reads live `iwconfig` state and
requires the AP SSID on `ra0` and `rax0` to match the corresponding DAT
profile. Each record is generated locally, and the resulting file is mode
`0600`.

## Startup ordering and readiness gates

The init service now:

1. Waits for `ra0` and `rax0` to report AP mode and a non-empty SSID in
   three consecutive samples; interface-directory existence alone is not
   considered ready.
2. Generates WTS from the two local DAT files before starting any EasyMesh
   daemon.
3. Starts WAPP and requires both expected Unix sockets:
   - `/tmp/wapp_server` — WAPP event/server endpoint.
   - `/tmp/wapp_ctrl` — WAPP control endpoint used by `wappctrl`.
4. Uses `wappctrl ra0 drv_version` and `wappctrl rax0 drv_version` to verify
   that WAPP registered both driver interfaces.
5. Runs the vendor WAPP v3.0.2.0 `mbo reset_default` command on both radios
   after the control socket is ready. Failure is fatal to WAPP startup.
6. Starts P1905 only after both WAPP sockets and both interface checks succeed,
   passing the generated WTS file through `-F`.
7. Starts MAPD after P1905, preserving the existing MAPD configuration and
   generated `/etc/mapd_strng.conf`.

A running PID without these sockets is not treated as a ready WAPP service.

## Build-time checks

GitHub Actions now:

- Runs the WTS generator against test-only DAT fixtures (never production
  credentials) and checks the exact three-record shape.
- Verifies WPA2/AES mapping, RRM enablement, hidden-SSID mapping, file mode,
  no 6 GHz profile, and rejection of vendor test SSIDs.
- Confirms that unsupported SAE and `RRMEnable=0` profiles fail without
  replacing the last valid WTS file.
- Checks the shipped WAPP binary for event registration, WAPP sockets,
  802.11k RRM, 11v/WNM BTM and BTM request API symbols.
- Checks MAPD steering/topology state-machine symbols and P1905 WTS/topology
  discovery symbols.

These checks prove that the binaries contain the expected code paths and that
the package wiring is syntactically consistent. They do **not** prove that the
live driver accepted event registration, that a neighbor was discovered, or
that a real client received and acted on a BTM request.

## Runtime acceptance criteria

The router-side validation is complete only when all applicable observations
are present:

- WTS has three generated records, correct live SSID values, no test SSIDs,
  and permissions `0600`.
- Both WAPP sockets exist and remain present while WAPP runs.
- P1905 logs successful WTS parsing (three BSS records) and sends topology
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

The current configuration already enables `SteerEnable=1` and
`CentralizedSteering=1`; the workflow also requires
`CONFIG_MTK_MBO_SUPPORT=y`. No additional guessed WNM/BTM DAT key is added:
the exact BTM request/response path must be verified against the live
7.6.7.3 driver and WAPP logs.
