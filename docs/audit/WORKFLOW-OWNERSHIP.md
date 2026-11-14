# N60 Pro workflow ownership

Status: consolidation in progress; build gates fail-closed
Maintenance branch: `runner/easymesh-patch-replay-20261114`
Target branch: `n60pro-mtk-closed-driver`
Scope: N60 Pro MT798x / ImmortalWrt 25.12 / Linux 6.12.112 / OpenSSL 3.5.9

## Current executable workflow ownership

| Workflow | Actual responsibility | Current policy |
|---|---|---|
| `easymesh-patch-replay.yml` | Consolidates EasyMesh patches 033–037 into the designated patch set and runs native OpenWrt EasyMesh `Build/Prepare` only | One manual/revision-triggered replay entry; **not** the complete 11-component vendor audit |
| `easymesh-quick.yml` | Invokes the EasyMesh compile/link composite action | Hard-frozen with `if: false` pending canonical audit attestation |
| `main.yml` | Full firmware compile/link | Hard-frozen with `if: false` pending canonical audit attestation |

The old ownership entries for `vendor-source-patch-audit.yml`,
`quick-prepare-audit.yml`, `openssl-migration-baseline-audit.yml` and
`component-source-diagnostics.yml` are not present on this branch and are not
treated as executable owners or as completed checks.

## Required single acceptance chain

The intended acceptance decision is one run-bound, exact-commit attestation. It must
cover, without duplicating workflow entry points:

1. The immutable vendor Lock and all 11 Lock-defined source components, archive SHA256
   verification, source path matrix and Quick/Full input-difference report.
2. Actual GNU Make-expanded package source variables and native OpenWrt download,
   unpack, overlay, patch and `Build/Prepare` ordering.
3. Vendor patch inventory and ordered replay with zero fuzz, zero offset, zero reject
   and zero partial application; distinguish network/download failures from source or
   patch incompatibilities.
4. MT Wi-Fi 026 real source path, patch result and function-replacement assertions;
   Conninfra, WARP, datconf and MAPFILTER coverage; datconf overlay/patch ordering.
5. EasyMesh consolidated patch replay, including the required 008/010/015/016 result,
   Lock consistency and byte-identical final source-tree parity.
6. Run/attempt/Git SHA/Lock SHA/input hashes and artifact digests in one authoritative
   credential. Preserve the eight original design/evidence artifacts and their
   existing SHA256 credentials.

The current replay workflow proves only its own consolidation and native EasyMesh
Prepare scope. It must not be relabeled as the complete vendor acceptance chain, and
its output alone must not authorize Quick or Full.

## De-duplication rules

- One canonical audit entry owns vendor Lock, archive integrity, source matrix, patch
  inventory/replay, MT Wi-Fi 026 assertions and native Prepare acceptance.
- Quick and Full consume the same exact-SHA attestation; they do not rerun the audit.
- Do not add separate vendor-audit and Quick-Prepare workflows that repeat the same
  source downloads or patch replay.
- OpenSSL semantic compatibility and Linux kernel patch-stack acceptance remain
  separate technical gates; do not combine them into a mega-audit or count their
  outputs as vendor-source evidence.
- Optional diagnostics run only on demand or on failure. Do not emit duplicate
  credentials or upload redundant success artifacts.
- Network failures are reported separately from source/patch failures. A faulty audit
  assertion is corrected in the audit tool; a correct vendor patch is not changed to
  satisfy a false positive.
- Preserve the existing eight design/evidence artifacts and SHA256 credentials.
- Do not enable either build job until the canonical attestation consumer has been
  implemented and tested against both valid and invalid/stale/wrong-SHA evidence.

## Change control

Before merging or deleting an audit owner, verify its callers, checks, artifacts and
downstream consumers. Transfer required checks into the canonical chain before
removing the old owner. Keep the workflow count small; reduce repeated execution,
not required technical coverage.
