# N60 Pro EasyMesh B-route hardening record

Date: 2026-11-01  
Branch: `n60pro-mtk-closed-driver`

## Changes applied

1. Added `easymesh-n60-validate-wts` and installed it in the `easymesh-n60` package. It fails closed unless the WTS file has the expected header, exactly 12 sequential records, wildcard MAC selectors, the N60 dual-band operating-class profile (4 × `11x`, 4 × `8x`, 4 × `12x` in the repository's existing row order), valid WAPP/P1905 core fields, and no 6 GHz rows.
2. The WAPP wrapper and init service both run the same validator before starting vendor daemons. This removes the previous difference where the init script checked only a record count while the wrapper performed a somewhat broader check.
3. The init service now validates the P1905 `al_inf` input before startup: it must be a real interface, distinct from `br_inf`, present in P1905's `bss_config_priority`, and have a valid nonzero unicast MAC. The actual interface/MAC pair is written to the system log before P1905 starts.
4. The standard firmware workflow checks the validator's presence and shell syntax, executes it against the tracked WTS template, and checks that the AL-interface guard remains in the init script.
5. Runtime logs showed the vendor child processes named `WAPP` (uppercase), while the wrapper and stop service previously searched/killed only `wapp` (lowercase). The wrapper now kills and waits for both process names, and the init stop service terminates both. This closes a real process-lifecycle/cleanup mismatch seen in the N60 runtime inventory.
6. The MAPD/P1905 source audit workflow now retains the SHA-256-verified MAPD, P1905 and mapfilter source archives plus their extracted trees as an Actions artifact, so later ABI and compile review can use the exact inputs rather than snippets alone.

## Validation boundary

The repository's WAPP, MAPD and P1905 executables remain prebuilt binaries. `easymesh-n60/Makefile` still has an empty `Build/Compile`; the changes above are startup/input validation and CI regression guards, not a rebuild of those vendor daemons.

The known runtime observation `do_map_set_ctl` / `sp update own almac to 00:00:00:00:00:00` is **not declared fixed** by the AL-interface preflight. The guard proves that the configured `al_inf` has a valid kernel netdevice MAC before daemon launch; if a daemon later overwrites its internal AL MAC with zero, the cause is inside the subsequent P1905/MAPD/WAPP control path and still requires source-level trace or runtime instrumentation.

Likewise, the vendor WAPP source findings (unchecked WTS parse results, unbounded `%s` fields, and swallowed BTM ioctl errors) are not corrected in the shipped WAPP ELF. The new validator reduces malformed-file exposure but cannot change the parser or event-delivery semantics inside that binary.

No DTS, partition, LED, MTK U-Boot, wireless-driver architecture, or radio DAT/WTS content was changed.
