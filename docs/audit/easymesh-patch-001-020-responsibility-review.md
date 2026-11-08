# EasyMesh patches 001-020 responsibility and overlap review

- Reviewed branch: `n60pro-mtk-closed-driver`
- Reviewed branch HEAD: `43c50f142213e9003f362e7555764c2e38371639`
- Scope: patch inventory, canonical vendor lock application order, package Prepare sequence, and existing DPP/MAP regression contracts.
- Status: static responsibility review only. No patch payload was rewritten and no Quick/Full build was started. A source-archive-backed replay is required before changing overlapping hunks.

## Inventory and responsibility

| Patch | Primary responsibility | Review |
|---|---|---|
| 001 | DSA PHY access via Linux MII ioctl | Separate; post-normalize target is `1905daemon`. |
| 002 | DPP parser safety | Broad legacy DPP scope; overlap must be resolved against 008/009/015/017/018. |
| 003 | WAPP GCC 14 copy semantics | Separate WAPP common parser/string-copy scope. |
| 004 | libmapd target compiler/linker flags | Separate build-system scope. |
| 005 | WAPP Hotspot realloc pointer arithmetic | Separate Hotspot allocation scope. |
| 006 | P1905 recursive Make toolchain propagation | Separate build-system scope; post-normalize. |
| 007 | OpenSSL 3 EVP_PKEY accessor compatibility | Separate API compatibility scope. |
| 008 | DPP parser bounds and secret-log redaction | Overlaps 002 and logging/lifecycle work in 017/018. |
| 009 | DPP NULL guard and unused credential-length cleanup | Narrow DPP cleanup; verify whether later patches supersede any hunk. |
| 010 | DPP WDEV allocation rollback | Overlaps ownership and rollback logic in 017/018. |
| 011 | WAPP WTS parser security | Main WAPP WTS hardening patch. |
| 012 | P1905 WTS parser hardening | Separate source/parser from WAPP WTS; retain as independent. |
| 013 | WAPP WTS fail-closed parser correction | Same source file and parser path as 011; explicit dependency/unique hunk needs replay proof. |
| 014 | WAPP WPS key log redaction | Narrow WPS log fix; compare against broad logging policy in 018. |
| 015 | DPP config lookup NULL/error guards | Overlaps DPP parser/query paths in 002/008. |
| 016 | DPP QR count bounds and error propagation | Distinct QR-specific responsibility; keep if replay and source contracts pass. |
| 017 | DPP credential bounds, zeroization, ownership and logging | Broad credential lifecycle scope; overlaps 010 and 018. |
| 018 | DPP security logging and credential lifecycle | Intended final DPP lifecycle/security layer; must be checked for duplicate cleanup and superseded earlier hunks. |
| 019 | WAPP MAP buffer and wire-length safety | Present in active lock despite prior decision to exclude it. |
| 020 | WAPP MAP packed-member/alignment and CAC timestamp handling | Same translation unit as 019, but alignment/timestamp responsibilities are distinguishable. |

## Confirmed lock/order facts

The canonical lock is `package/mtk/vendor-sources.lock.json`. Its current EasyMesh application order includes:
- DPP: 002, 007, 008, 009, 010, 015, 016, 017, 018
- WAPP/P1905 parsing and logging: 011, 014, 012, 013
- Build/compatibility: 003, 004, 005
- MAP: 019, 020
- Post-normalize: 006, then 001 (001 uses the `1905daemon` root suffix).

Important inconsistency: the active lock still includes `019-wapp-map-buffer-safety.patch`, even though the project decision recorded for this series was to exclude 019. The patch file also remains in the patch directory. This is not yet corrected because the existing `test-wapp-map-buffer-contract.py` explicitly checks behavior currently supplied across the 019/020 stack; dropping 019 without first identifying and relocating every required invariant would break the regression contract or silently remove safety coverage.

## Overlap findings requiring source-backed adjudication

### DPP
1. Compare 002 vs 008 at function/Hunk level. Keep parser ownership and baseline guards in one clearly identified layer; do not duplicate checks with divergent return semantics.
2. Compare 008 vs 015 around parameter lookup and error propagation.
3. Compare 009 vs 017/018 around credential pointer validity, length fields, and temporary-object cleanup.
4. Compare 010 vs 017/018 around allocation failure rollback, config replacement, and cleanup labels. For every pointer, document owner, transfer point, wipe length, free site, and rollback owner. Prove no double-free and no leak on each exit.
5. Treat 018 as the final lifecycle/logging layer only where its hunks are additive and correct. Do not retain earlier duplicate cleanup just to preserve patch count.
6. Compare 014 with 018's WPS/DPP logging policy. Keep 014 only if it covers a distinct WPS event not already covered by the later patch.

### WAPP WTS
1. 011 and 013 both modify `wappd/common/main.c` in the WTS parser path.
2. Verify that 013's fail-closed change is not already present in 011 after application.
3. If unique, preserve it as a narrowly scoped dependent correction; if redundant, fold the unique required behavior into the canonical WTS patch and remove the duplicate application entry only after replay.
4. Verify struct layout, field capacities, event lengths, alignment, BSS count bounds, and fail-closed rollback using the original WAPP source as the sole baseline.

### WAPP MAP
1. 019 and 020 both modify `wappd/map/map_1905.c`; shared-file overlap alone is not proof of duplicate behavior.
2. Separate wire-format/buffer sizing from packed-member/alignment/timestamp access.
3. The existing MAP contract test includes invariants for flexible tails, event lengths, CAC wire lengths, zero-opcap handling, and packed alignment. Determine which invariant is introduced by each patch before excluding or rewriting either one.
4. The earlier exclusion decision for 019 must be reconciled with the active lock and regression test. Do not simply delete the patch or weaken the test.

## Required acceptance before source patch edits

- Reconstruct exact application sequence from the canonical lock and native Package Prepare path.
- Replay the complete 001-020 series against the exact locked vendor archives, preserving per-patch before/after tree hashes and logs.
- Record every Hunk's target file/function and classify it as unique, additive, superseded, conflicting, or redundant.
- Verify DPP pointer ownership and every success/failure cleanup path by source inspection and regression tests.
- Verify WAPP WTS structure layout, buffer capacities, event lengths, and alignment.
- Verify MAP flexible-array capacity, wire lengths, packed-member access, and CAC timestamp handling.
- Reconcile 019 exclusion with the canonical lock, source behavior, and regression tests.
- Preserve all existing audit design artifacts and SHA256 credentials; any changed lock digest must generate a new run/commit-bound audit credential rather than reuse an old pass.
- Run the full fixed-vendor source/patch audit before Quick Prepare. Do not start EasyMesh compile/link until every gate passes.

## Change decision

No source patch or canonical lock entry is changed by this review commit. The branch currently has a demonstrable lock-vs-decision inconsistency for 019 and several DPP/WAPP overlap questions whose safe resolution depends on exact source-backed patch replay. Making speculative edits without those exact replay results would risk modifying correct vendor fixes or breaking the existing regression contract.

## Follow-up: static hunk overlap review and minimal patch cleanup

This section supersedes the earlier statements that the active 019 patch should be excluded. The current project correction is that the active MAP patch `019-wapp-map-buffer-safety.patch` is retained; the historical/obsolete 019 reference is a different item and must not be confused with this file.

- Follow-up branch base: `b080ed3b5fce23077bb5605e706a5a00f396ef4b`
- Follow-up resulting branch HEAD: `7830c077117959bf8e5425a343f2d52e36242404`
- Canonical Lock was not changed; its blob remains `26dc245b7d94009143531143a989c36adf514b80`.
- No changes were made to the eight original design artifacts or their stored SHA256 credential files.

### Minimal corrections committed

1. `013-wapp-wts-parser-fail-closed.patch`
   - Removed the second hunk that deleted the post-increment `i >= max_bss_num` guard.
   - Patch 011 already moves the BSS bound check to the top of the parser iteration and removes that old post-increment guard. Keeping the deletion in 013 duplicated a change already made by 011 and could make 013 search for context that no longer exists.
   - Retained 013's unique hidden-SSID malformed-format change from `break` to `goto err`.
   - New blob: `f7e1a0002379369240bc02e0e1ac8c59332cf023`.
   - Commit: `9bd189c4909be45b0f604d781fc6baa17b5957df`.

2. `020-wapp-map-packed-member-gcc14.patch`
   - Removed the CAC pointer-index hunk at old source line 7428.
   - Patch 019 already changes the allocation from a stack object to a pointer and changes both the `cac_status` object access and `ongoing_cac_channel_num` access to pointer syntax. The old context in 020 still used `cac_status.ongoing_cac_channel_num`, so it was superseded by 019 and could not apply to the post-019 tree.
   - Retained 020's packed CAC timestamp read/write via byte-offset plus `memcpy`, CAC list bound check, and bounded policy VID copy.
   - New blob: `9e386d9e2e4207b309ba1701076647d668c8537b`.
   - Commit: `7830c077117959bf8e5425a343f2d52e36242404`.

### Revised overlap classification

| Group | Classification after cleanup | Remaining work |
|---|---|---|
| 002 / 008 | Caller-side DPP parameter validation versus shared getter capacity/error contract; dependent, not duplicate by itself | Replay exact source; verify getter's OPENWRT and non-OPENWRT branches and every caller's error handling |
| 002 / 009 | 009 removes unused `cred_len` and corrects MAP_R3-only `dev_list` initialization; narrow follow-up | Verify preprocessor configurations and no stale declaration/use |
| 010 / 017 / 018 | Same config ownership/cleanup region; additive rollback and zeroization layers, with potential lifecycle conflicts | Build pointer ownership table from actual source; check every success/error exit for one free, correct wipe length, and no stale alias |
| 008 / 014 / 018 | Logging policy overlap, but 014's WPS event is separate from 018's DPP/test-file and DPP diagnostic changes | Search final preprocessed source for remaining key/passphrase/PMK/PTK/connector/private-key output |
| 011 / 013 | One redundant 013 hunk removed; remaining hidden-SSID fail-closed correction is unique | Replay 013 after 011 and prove zero offset/fuzz |
| 012 | P1905 daemon WTS parser, separate from WAPP parser | Keep independent; test parser state rollback and BSS bounds |
| 019 / 020 | Superseded pointer hunk removed from 020; remaining 020 work is packed-member/alignment and CAC timestamp handling | Replay 019 then 020; validate actual packed struct layout, flexible tails, event length, and wire encoding |

### Replay limitation and gate

This follow-up was a patch-to-patch static hunk comparison. The locked WAPP vendor source archive is a binary release asset; the available repository file reader returned text files but could not retrieve that binary archive for extraction in this session. Therefore this update does **not** claim source-backed replay, zero-fuzz/zero-offset acceptance, DPP lifecycle proof, WAPP WTS regression success, or MAP/GCC14 compilation.

The Lock digest did not change, but two patch inputs did. Any prior audit credential bound to the old patch blobs/commit is stale for this tree. The next fixed-vendor audit must hash the new patch blobs and bind a fresh credential to the resulting commit/run/attempt. Preserve the eight original design artifacts and all existing credentials as historical evidence; do not overwrite or reuse them as a pass for this revision.

No EasyMesh Quick or Full compile/link was started. The complete fixed-vendor audit, exact locked-source patch replay, Quick Prepare, and MT Wi-Fi 026 path/application/function assertions remain mandatory gates.

## Correction: conclusions verified against failed Action source evidence (2026-11-09)

The exact logs and uploaded source artifacts from runs `42532859637` and `42532859725` falsified two statements in the preceding static review. This section supersedes those two statements.

1. **Patch 019 CAC pointer indexing was not fully converted.**
   - The fixed-vendor audit completed the archive/patch stage and reached the real native EasyMesh `prepare` target, where `test-wapp-map-buffer-contract.py` failed with `CAC flexible-tail index still uses pointer as a struct object`.
   - The uploaded fully patched WAPP source showed three expressions of the form `cac_status->cac_ongoing_channel[cac_status.ongoing_cac_channel_num]`. The pointer base used `->`, but the flexible-tail index still used `.`. The regression assertion was correct; this was a real patch defect, not a false positive.
   - Corrected all three index expressions in `019-wapp-map-buffer-safety.patch`.
   - Correction commit: `a83eeb27320b47bc03e4374281f0df2bce6cef65`.
   - New Git blob: `af8eaf3679b6039182143f10825d9f48112c5b1a`.

2. **Patch 011 did not remove the WAPP post-write truncation guard.**
   - WAPP source audit run `42532859725` failed at the assertion `WAPP legacy post-write truncation remains`. Its uploaded `wapp-post-011/main.c` was captured immediately after patch 011 and showed the post-write block still present: increment `i`, test `i >= max_bss_num`, decrement `i`, and `break`.
   - The prior claim that patch 011 had already removed this block was incorrect. The source-audit assertion is valid for the complete patch stack: patch 013 must remove the residual block after patch 011.
   - Restored the narrowly scoped deletion hunk to `013-wapp-wts-parser-fail-closed.patch`, retaining its unique malformed hidden-SSID `goto err` correction.
   - Correction commit: `6bd84694917b7fa06a610540842cab8316a021d4`.
   - New Git blob: `7089ea82e3d0d2ca3092c3f806824452c196d8a8`.
   - Local replay against the exact post-011 WAPP source artifact passed `patch --dry-run --batch --forward --fuzz=0`; after application, the pre-write BSS bound remained before indexed writes, the post-write decrement/truncation block was absent, and the hidden-SSID malformed path remained fail-closed.

3. **Action and credential disposition.**
   - Run `42532859637` failed at native EasyMesh Prepare, after the fixed-vendor patch series had been applied. Its uploaded patch report and DPP/source artifacts remain preserved.
   - Run `42532859725` failed at the WAPP parser source assertion, not at source download. Its post-011 WAPP and P1905 source artifacts remain preserved.
   - The new patch inputs require fresh Lock/patch/input hashes and a new commit/run/attempt-bound audit credential. Existing eight design artifacts and prior SHA256 credentials remain historical evidence and must not be overwritten or reused as a pass.
   - Do not start Quick or Full compile/link until the new complete fixed-vendor audit, WAPP source audit, native Quick Prepare, and MT Wi-Fi 026 path/application/function assertions all pass on the same applicable revision/evidence chain.

## Patch-preimage and unified-diff escaping correction (2026-11-09)

Two follow-up Action attempts exposed mechanical defects in the first corrections above. They are corrected in the current branch; the intermediate failed attempts remain part of the audit history.

- The first 019 edit accidentally changed the **deleted preimage** lines as well as the replacement lines. WAPP source audit run `42533454089` reported `Hunk #8 FAILED at 7406`. The final 019 patch restores the vendor-source preimage exactly (`cac_status.cac_ongoing_channel[cac_status.ongoing_cac_channel_num]`) and changes only the new pointer-based result to `cac_status->cac_ongoing_channel[cac_status->ongoing_cac_channel_num]` for all three fields.
  - Final correction commit: `8027a9ddbd4f5aa8c7579a3626313c8bae96d414`.
  - Final 019 blob: `b12cd31478ee32400ebcacfc6565a2ca5683b9c6`.
- The first restored 013 deletion hunk encoded the C string newline as a double backslash in the patch text. That caused the post-011 context hunk to fail. The patch now contains the same single-backslash C escape as the captured vendor source.
  - Final 013 correction commit: `75d2e283463047edfa368387190bf26616798e70`.
  - Final 013 blob: `6ef4bd9da3583bb9419210d2ed4df40f16ed9a2e`.
- The final 013 deletion hunk was independently dry-run and applied against the exact uploaded post-011 WAPP parser source with `--batch --forward --fuzz=0`; its parser assertions passed locally. The current 019 diff has the original vendor preimage on the removed side and the pointer-safe member/index expressions on the added side.
- Runs `42533453959` and `42533454089` are failed attempts against the intermediate 75d/8027 predecessor revisions and must not be counted as validation of the corrected final patch pair. The current branch head is `8027a9ddbd4f5aa8c7579a3626313c8bae96d414`; wait for and inspect the newly triggered full vendor and WAPP source audits at this exact HEAD.
- The eight original design artifacts and all pre-existing SHA256 credentials remain preserved. Fresh audit evidence must be produced for the final patch blobs and exact HEAD; Quick/Full remain frozen.


## Follow-up: DPP saved-config parser and patch-offset correction

The f50de8 revision exposed a patch-tooling defect rather than a vendor-source defect: the newly added dpp_wdev hunks applied with nonzero offsets (-12 and +119 lines), and the hunk metadata no longer described the source context accurately. The failed Action stopped at patch replay; its Quick Prepare job did not run.

The entire dpp_wdev section of patch 018 has now been regenerated from the exact post-017/pre-018 source snapshot to the intended final source. The saved-config parser now rejects empty Connector, NetAccessKey, and C-Sign values; validates even hex lengths and decoded byte capacities; allocates buffers by decoded byte length and populates them with wpabuf_put_data; and sends parse, allocation, formatting, and DPP-enable failures to a common cleanup path. The temporary decoded-key buffer is cleared on success and failure, and the caller clears any partially allocated credentials before freeing its temporary auth object.

The regenerated dpp_wdev diff was replayed locally against the captured pre-018 source with --fuzz=0: all seven hunks applied, with no offsets or rejects. The source-contract tests were updated to assert the new decoded-byte and rollback behavior. The prior successful Quick Prepare run 42536107069 belongs to the earlier commit 7be9575debebfa1514e0565b266783b7fa59f455 and does not attest this revision. A fresh fixed-vendor audit and Quick Prepare credential are required. The eight original design artifacts and all previous SHA256 credentials remain preserved; this change does not start EasyMesh compile/link or Full.
