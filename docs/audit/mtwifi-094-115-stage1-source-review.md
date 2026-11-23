# MT Wi-Fi 7.6.7.3 patches 041 and 094–115 — source audit checkpoint

- Repository: `laodadelaoda/immortalwrt-mt798x-rebase`
- Branch: `n60pro-25.12-upstream-base`
- Audited commit: `63d6bcd13bbe2fa65e1053792d6fa9f431785c32`
- Patch directory: `package/mtk/drivers/mt_wifi/patches-7673/`
- Vendor source archive: `mt79xx_20250408-705eb4.tar.xz`
- Vendor archive SHA256: `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78`
- Uploaded source bundle SHA256: `0973e5770bc899b7749c92ec7e07127bfc6d0689ef1a7d72f02ef01db7694cea`

The vendor archive hash matches `PKG_HASH` in `package/mtk/drivers/mt_wifi/Makefile`. The archive was extracted and the original MT Wi-Fi source tree was inspected. All semantic notes below are source-based; runtime/hardware behavior still requires the later Full build and N60 Pro tests.

## Patch inventory and ordering

The `patches-7673` directory contains the active 001–041 and 094–115 patches; there are no 042–093 patch files in this directory. The package Makefile selects this directory for driver version 7.6.7.3 and uses `PATCH := patch --fuzz=0`.

- Patch 041 is an RX header-translation port-security fix in `cmm_data.c`; it is independent of the BTM payload group.
- 094–096 share BTM variable-length structures and WNM IOCTL/event boundaries.
- 107 and 113 jointly govern APCLI interface-down/autoconnect behavior.
- 114 and 115 extend the BTM payload/bounds path and must remain ordered after the shared BTM definitions/handlers.

## Source-based patch classification

| Patch | Source finding | Classification / disposition |
|---|---|---|
| 041 | The old header-translated RX path performed a second `MacTableLookup(Addr2)` and dereferenced the result without checking for a miss. The RX-WCID path already supplies the associated `pEntry`; `TRTableInsertEntry(pAd, pEntry->wcid, pEntry)` maps its WCID into the TR table. Using that peer avoids the fallible duplicate lookup and keeps port security tied to the RX peer. | Valid functional RX safety fix; no BTM dependency found. |
| 094 | Converts four zero-length BTM payload arrays in `oid.h` to C flexible array members. The payload remains the final member; `sizeof` still describes the fixed header and `offsetof` identifies the payload start. | Correct C layout declaration; prerequisite for safe variable-length payload handling. |
| 095 | Adds null/allocation/length checks to WNM BTM query/response/request event producers and validates AP/STA BTM event headers, MBSS/APCLI indices, payload lengths and copies. The 0xff cap is required where the new `wnm_event.event_len` is an 8-bit field. | Functional bounds and allocation hardening. |
| 096 | Checks user IOCTL lengths before copy/dereference, bounds nested command and BTM payload lengths, handles allocation/copy failures, and updates BTM request allocation state on failure. | Functional IOCTL/memory-safety hardening. |
| 097 | Skips ACK/CTS timeout programming when `ack_cts_enable[idx]` is disabled, preserving firmware defaults. | Functional configuration guard. |
| 098 | Adds an explicit 2.4 GHz VHT channel-band case and a missing break so 2.4 GHz does not enter VHT80/160 channel-group logic. | Functional channel-band handling. |
| 099 | Tracks when RX channel selection intentionally remaps the receiving wdev and suppresses only the otherwise-false original-band mismatch check in that case. | Functional RX channel/wdev consistency fix. |
| 100 | Skips PHY adjustment while `cfg->prim_ch == 0`, the unconfigured ACS placeholder, until a primary channel is selected. | Functional initialization guard. |
| 101 | Channel 0 is an unconfigured ACS placeholder. Without the early return, `RcGetHdevByChannel()` can match a radio currently holding channel 0 and return its band (potentially BAND1); the early return consistently chooses BAND0, matching `HcGetBandByChannelRange()`'s default. | Functional default-band correction. Renamed to `101-hdev-ctrl-channel-zero-band0-default.patch`; the old “diagnostic” filename was inaccurate. |
| 102 | Changes the BSS-not-ready beacon message from ERROR to INFO and rewrites its text. | Log-only; no beacon behavior change. |
| 103 | Changes missing optional debug profile-key messages from ERROR to INFO. | Log-only; no profile behavior change. |
| 104 | Changes the lower-level `TxCCKStreamCtrl()` range check from `>= WF_NUM` to `> WF_NUM`, allowing the documented upper value 4 when `WF_NUM == 4`. Its hunk line 21130 is valid only in the complete ordered series; the full replay confirms zero offset. | Functional range-boundary correction for the MT7622 implementation. |
| 105 | Aligns the `SetCCKTxStream()` front-end range check and adds an explicit MT7622-only guard. The underlying `TxCCKStreamCtrl()` issues `MtCmdTxCCKStream()` only for MT7622. | Valid chipset guard. It does not enable CCK Tx stream control on N60 Pro MT7986. |
| 106 | Changes one missing optional L1 profile index message from ERROR to DEBUG. | Log-only. |
| 107 | Prevents APCLI auto-connect/candidate switching from continuing while the APCLI interface is down and clears the in-flight running state. The repeater periodic path separately checks interface-up and Enable before restarting scans. | Functional APCLI state guard; reviewed together with 113. |
| 108 | Replaces the combined 2G-plus-(5G-or-6G) EEPROM test with a per-`Channel_Band` indication-bit selection: band 0 uses DPD2G, band 1 DPD5G, band 2 DPD6G; invalid bands return. A missing band-specific pre-cal payload returns from the preload helper while the channel-switch path continues. | Functional MT7986 DPD selection correction. N60 Pro remains configured for 2.4/5 GHz; this patch does not authorize enabling 6 GHz. |
| 109 | The affected Tx-power routines are existing unsupported stubs; this patch changes diagnostics/severity, not the implementation. | Log-only; does not implement per-rate Tx power or compensation. |
| 110 | The HIF_MT antenna helper already returns without configuring antenna state; this patch changes the message/severity only. | Log-only; does not implement antenna configuration. |
| 111 | Propagates `chip_cmd_tx()` / `MtCmdCr4RedSet()` failure status through RED command handling and avoids reporting success when the MCU command fails. | Functional command-status correction. |
| 112 | Changes the already-initialized IP/MAC table message from ERROR to DEBUG. | Log-only. |
| 113 | Allows disabling an already-down APCLI as a successful no-op, clears its in-flight autoconnect state, and continues to reject enabling while the interface is down. The repeater loop checks interface-up and Enable before scheduling a new scan. | Functional APCLI disable/init guard; reviewed together with 107. |
| 114 | In addition to output allocation/IE length checks, validates the outer BNDSTRG ioctl length, nested WNM command length, minimum BTM request length and the appended 34-byte neighbor-record prefix plus RRM payload before the driver reads them. Malformed input returns `BND_STRG_INVALID_ARG`. | Functional input/output bounds hardening. Full ordered replay passes all 11 hunks with zero fuzz/offset. |
| 115 | Validates APCLI index, peer/payload pointers and BTM response length before indexing WNM state or copying into the flexible event payload. | Functional STA BTM response bounds hardening. |

## Dependency and hardware constraints

1. 094 must precede the BTM payload consumers/producers in 095, 096, 114 and 115; these patches use fixed-header `sizeof` and flexible-payload `offsetof` consistently.
2. 114's BNDSTRG payload layout is `btm_req_len` bytes followed by the 34-byte index/SSID prefix and the RRM neighbor record. The new nested-length check verifies the source command contains the complete layout before the driver advances by 34 bytes.
3. 107 and 113 are complementary: one stops/clears work when APCLI is down; the other makes an explicit disable request idempotent while down. The periodic repeater path checks interface-up and Enable before restarting scans.
4. 041 binds port security to the RX-WCID-selected peer and does not depend on the BTM group.
5. 104/105 are MT7622-specific. They must not be described as enabling CCK Tx stream control on MT7986.
6. 108 selects calibration data only for the current RF band. The N60 Pro configuration must continue to expose only its supported 2.4/5 GHz bands; do not enable 6 GHz by inference from generic driver tables.
7. 102, 103, 106, 109, 110 and 112 are diagnostic/log changes only. Do not count them as new hardware functionality.

## Canonical replay and Prepare evidence

- Successful run: [#45104536870](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/45104536870)
- Audited commit: `63d6bcd13bbe2fa65e1053792d6fa9f431785c32`
- Run attempt: `1`
- Active patch files across the fixed vendor/EasyMesh patch series: `146`
- Patch failures: `0`
- Fuzz: `0`
- Offset: `0`
- Reject: `0`
- Patch 114: `11/11` hunks applied, zero fuzz/offset.
- MT Wi-Fi 026 exact Prepare path, patch result and function-replacement assertions: passed.
- Native OpenWrt Prepare: MT Wi-Fi, Conninfra, WARP, MAPFILTER, datconf and EasyMesh passed.
- No feeds, host tools, target toolchain, kernel build, package compilation or Full firmware compilation was run.
- Canonical audit artifact: `n60pro-canonical-vendor-audit-45104536870-attempt-1`
- Lock path: `package/mtk/vendor-sources.lock.json`
- Lock SHA256: `6d6e49fb766feb951eee97ed686f3567ed55c68505fbd1cd4635362f4a52abb2`
- The run-bound `vendor-audit-attestation.json` records all acceptance checks as passed for the exact commit and lock.

## Acceptance status

- [x] Correct repository branch and native package patch directory identified.
- [x] Original MT Wi-Fi archive SHA256 verified against package `PKG_HASH`.
- [x] 041 and 094–115 source paths/call relationships reviewed.
- [x] 101 correctly classified as a functional default-band fix and renamed.
- [x] 102/103/106/112 and 109/110 correctly classified as log-only.
- [x] 104/105 correctly scoped to MT7622, not MT7986.
- [x] 114 nested BNDSTRG/BTM source-length guard added and replayed.
- [x] Full fixed-vendor/EasyMesh patch replay passed on commit `63d6bcd13bbe2fa65e1053792d6fa9f431785c32`: 146 active patch files, zero failures/fuzz/offset/reject.
- [x] Native OpenWrt Prepare and MT Wi-Fi 026 assertions passed.
- [ ] Remaining cross-patch semantic review outside this MT Wi-Fi subset.
- [ ] Full firmware compile (blocked until all required semantic/audit gates pass).
- [ ] N60 Pro hardware validation of boot, MTK Wi-Fi and EasyMesh cooperation.

**Full-build safety:** the old push-triggered Full job from run #45102576748 was cancelled by the new `cancel-stale-full` concurrency guard. Push/PR events now run audits only. Full requires a successful canonical audit plus manual `workflow_dispatch` with `run_full=true`; the input defaults to false. Run #45104536870's firmware job was skipped. Do not treat successful patch replay/Prepare as Full-build or hardware acceptance.
