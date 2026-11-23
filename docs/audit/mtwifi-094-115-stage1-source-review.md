# MT Wi-Fi 7.6.7.3 patches 094–115 — Stage 1 source review

- Repository: `laodadelaoda/immortalwrt-mt798x-rebase`
- Branch: `n60pro-25.12-upstream-base`
- Reviewed repository HEAD: `f6cde2774f147c6b07905fc4b276c2914a95e29b`
- Patch directory: `package/mtk/drivers/mt_wifi/patches-7673/`
- Vendor source archive: `mt79xx_20250408-705eb4.tar.xz`
- Vendor archive SHA256: `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78`
- Uploaded source bundle SHA256: `0973e5770bc899b7749c92ec7e07127bfc6d0689ef1a7d72f02ef01db7694cea`

The vendor archive hash matches `PKG_HASH` in the branch's `package/mtk/drivers/mt_wifi/Makefile`. The archive was extracted and the original MT Wi-Fi source tree was inspected. This is a source-level checkpoint, **not yet a complete patch replay or acceptance report**.

## Patch inventory and order

The selected `patches-7673` directory contains patch 041 followed by 094–115. There are no 042–093 files in this directory. The package Makefile selects this directory for driver version 7.6.7.3 and sets `PATCH := patch --fuzz=0`.

The 094–096 and 114–115 group concerns BTM variable-length payloads and event/IOCTL boundaries. Their shared structures and length arithmetic must be reviewed together. 107 and 113 both affect APCLI state transitions and must be checked as a pair. 041 is a separate `cmm_data.c` change; no direct dependency on the BTM group has been established yet.

## Confirmed source observations

| Patch | Source-based observation | Provisional classification |
|---|---|---|
| 101 | `Channel == 0` is an unconfigured ACS placeholder. Without the early return, `RcGetHdevByChannel()` can match a radio currently holding channel 0 and return its band index (potentially BAND1); the early return consistently chooses BAND0, matching `HcGetBandByChannelRange()`'s default. | Functional default-band correction; not log-only. The patch filename was corrected to describe the actual behavior. |
| 102 | Changes the BSS-not-ready beacon message from ERROR to INFO and rewrites its text. | Log-only. |
| 103 | Changes missing optional debug profile-key messages from ERROR to INFO. | Log-only. |
| 104 | Changes the `SetCCKTxStream()` upper-bound check from `>= WF_NUM` to `> WF_NUM`, but the called `TxCCKStreamCtrl()` still rejects `u1CCKTxStream >= WF_NUM`. `WF_NUM` is 4. Therefore value 4 passes the front-end check but is still rejected by the lower-level control path. | Incomplete functional change; repair must reconcile both validation layers and verify firmware semantics before claiming four-stream support. |
| 105 | Adds an MT7622-only guard to the `SetCCKTxStream()` ioctl path. The underlying `TxCCKStreamCtrl()` also only issues `MtCmdTxCCKStream()` for MT7622. | Valid chipset guard candidate; verify profile/startup path and ensure unsupported chipsets do not retain misleading settings. |
| 106 | Changes one missing optional L1 profile index message from ERROR to DEBUG. | Log-only. |
| 108 | Changes DPD preload selection from a combined 2G-plus-(5G-or-6G) EEPROM test to a per-`Channel_Band` indication bit. The vendor source contains distinct 2G, 5G and 6G pre-cal tables for MT7986. | Functional calibration-selection change; verify bit mapping, band mapping, EEPROM states and N60 Pro's enabled RF bands. |
| 109 | The two affected Tx-power routines are existing unsupported stubs; this patch changes their diagnostics and severity, not the implementation. | Log-only; does not implement per-rate Tx power or compensation. |
| 110 | The HIF_MT antenna helper already returns without configuring antenna state; this patch changes the message/severity only. | Log-only; does not implement antenna configuration. |
| 112 | Changes the already-initialized IP/MAC table message from ERROR to DEBUG. | Log-only. |

## Dependency and replay focus

1. Replay 094–096 as a BTM/IOCTL group, checking all `sizeof`, `offsetof`, message-length and copy-length relationships against the original headers and event producers/consumers.
2. Replay 114–115 with the BTM group. Verify the flexible payload start, allocation size, IE length byte, appended Neighbor Report and BSS Preference lengths, and station BTM response event length.
3. Review 107 and 113 together for APCLI interface-down semantics, `ApCliAutoConnectRunning`, and the return contract of callers.
4. Review 097–100 and 111 against their actual call paths and hardware/firmware interfaces.
5. Resolve 104/105 only after confirming the MT7622 firmware command's valid CCK stream range. N60 Pro is MT7986; these patches must not be represented as enabling CCK Tx stream control on MT7986.
6. Do not classify 101/102/103/106/109/110/112 as functional hardware fixes merely because they have numbered patches.

## Acceptance status

- [x] Correct branch and patch directory identified.
- [x] Vendor source archive SHA256 verified against package `PKG_HASH`.
- [x] Original source extracted and selected function paths inspected.
- [x] Initial source-based classifications recorded.
- [x] Full ordered vendor patch replay completed: 146 active patch files, zero patch failures, zero fuzz and zero offset reported.
- [x] Native OpenWrt Prepare completed for MT Wi-Fi, Conninfra, WARP, MAPFILTER, datconf and EasyMesh; no package compilation was run.
- [x] MT Wi-Fi 026 exact Prepare-path and patched-function assertions passed.
- [x] Patch 104 original hunk header retained; full ordered series, not pristine-source-only testing, is the authoritative replay context.
- [x] Full 094–115 patch replay in native package order (run #45102576748; audited commit ac38289b6945d3273734f5ed0a84cd1bc5501b9b).
- [x] Zero Fuzz, zero Offset, zero Reject, zero partial application proven for the active vendor patch series by the successful audit gate.
- [ ] Complete semantic dependency/overlap audit, including patch 041 and the 107/113 pair; successful replay alone does not prove runtime correctness.
- [ ] Evidence-backed patch corrections and final source replay.
- [ ] Full build (blocked until all preceding gates pass).
- [ ] N60 Pro hardware acceptance.

**Build scheduling exception:** run #45102576748 was triggered by the checkpoint commit before the Full workflow gate was tightened. Its vendor audit completed successfully, and the firmware job is currently queued/pending under the older workflow revision. The connected GitHub actions controls available in this session do not expose a cancel-run operation, so this already-created job cannot be cancelled here. The branch workflow has since been changed so future pushes/PRs cannot start Full; a future Full requires manual workflow dispatch with `run_full=true` (the input defaults to false). Do not interpret the queued job as authorization to start Full before semantic review is complete.
