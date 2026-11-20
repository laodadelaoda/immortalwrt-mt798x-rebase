# N60 Pro EasyMesh B-route hardening record

Date: 2026-11-01  
Branch: `n60pro-mtk-closed-driver`

## Changes applied

1. Added `easymesh-n60-validate-wts` and installed it in the `easymesh-n60` package. It fails closed unless the WTS file has the expected header, exactly 12 sequential records, wildcard MAC selectors, the N60 dual-band operating-class profile (4 × `11x`, 4 × `8x`, 4 × `12x` in the repository's existing row order), valid WAPP fields plus the three trailing P1905 VLAN/PVID/PCP tokens, and no 6 GHz rows.
2. The WAPP wrapper and init service both run the same validator before starting vendor daemons. This removes the previous difference where the init script checked only a record count while the wrapper performed a somewhat broader check.
3. The init service now validates the P1905 `al_inf` input before startup: it must be a real interface, distinct from `br_inf`, present in P1905's `bss_config_priority`, and be queryable through WEXT in `Mode:Master`, and have a valid nonzero unicast MAC. The actual interface/MAC pair is written to the system log before P1905 starts.
4. The standard firmware workflow checks the validator's presence and shell syntax, executes it against the tracked WTS template, and checks that the AL-interface guard remains in the init script.
5. Runtime logs showed the vendor child processes named `WAPP` (uppercase), while the wrapper and stop service previously searched/killed only `wapp` (lowercase). The wrapper now kills and waits for both process names, the init stop service terminates both, and the read-only diagnostic process inventory displays both names. This closes a real process-lifecycle/cleanup mismatch seen in the N60 runtime inventory.
6. The MAPD/P1905 source audit workflow now retains the SHA-256-verified MAPD, P1905 and mapfilter source archives plus their extracted trees as an Actions artifact, so later ABI and compile review can use the exact inputs rather than snippets alone.

## Validation boundary

The current package does not use the legacy prebuilt WAPP, MAPD and P1905
executables as firmware payloads. `easymesh-n60/Makefile` extracts pinned
vendor source archives, applies compatibility and hardening changes, compiles
WAPP, wappctrl, MAPD and P1905 for AArch64, builds
`libeth_1905ops.so` and `libmapd_interface_client.so`, and installs those
build outputs. Legacy ELF files under `files/usr/bin` and `files/usr/lib`
are retained as audit references; current install rules do not install them.

WAPP WTS parser hardening is applied to source during Build/Prepare, before
WAPP is compiled. DPP parser bounds, error propagation, allocation rollback
and secret-log redaction are also covered by source patches and semantic
source-contract tests. These changes are included in the newly built binaries
only when Build/Prepare and Build/Compile both complete successfully. A static
test or a successful source-audit workflow alone does not prove a successful
target build.

The known runtime observation `do_map_set_ctl` /
`sp update own almac to 00:00:00:00:00:00` is **not declared fixed** by the
AL-interface preflight. The guard proves that configured `al_inf` has a valid
kernel netdevice MAC before daemon launch; if a daemon later overwrites its
internal AL MAC with zero, the cause is inside the subsequent P1905/MAPD/WAPP
control path and still requires source-level trace or runtime instrumentation.

The WAPP source audit also identified BTM ioctl error-propagation behavior.
The current hardening work must not be described as fixing that behavior unless
a dedicated source patch and regression test explicitly cover it. Successful
compilation still does not prove live driver event registration, topology
discovery, or successful 11v BTM steering.

No DTS, partition, LED, MTK U-Boot, wireless-driver architecture, or radio DAT/WTS content was changed.
