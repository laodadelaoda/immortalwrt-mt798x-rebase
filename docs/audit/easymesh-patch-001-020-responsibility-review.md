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
