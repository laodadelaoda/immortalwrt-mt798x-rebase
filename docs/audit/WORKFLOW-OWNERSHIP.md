# N60 Pro workflow ownership

Status: simplified responsibility baseline
Maintenance branch: `n60pro-mtk-closed-driver`
Scope: N60 Pro MT798x / ImmortalWrt 25.12 / Linux 6.12.112 / OpenSSL 3.5.9

This matrix records only workflows that own an operational project task. It is not a
requirement to create a separate workflow for every audit or helper script.

## Retained workflow set

| Workflow | Responsibility | Invocation |
|---|---|---|
| `vendor-source-patch-audit.yml` | Canonical vendor Lock/archive/SHA256/patch replay and MT Wi-Fi 026 audit; emits the vendor attestation | Reusable, manual, dedicated documentation trigger |
| `quick-prepare-audit.yml` | Reusable no-firmware-build native Prepare and target compatibility checks; consumes exact-SHA evidence | Called by Quick and Full only |
| `easymesh-quick.yml` | Quick entry point; calls vendor audit then Prepare in order | Manual only; build job remains frozen |
| `main.yml` | Full entry point; calls the same vendor and Prepare gates; includes kernel preflight | Manual only; build job remains frozen |
| `openssl-migration-baseline-audit.yml` | Target-preprocessor/API-gate regression tests; optional manual 68-item header traceability | Push/PR regression; manual traceability only |
| `component-source-diagnostics.yml` | On-demand WAPP/DPP, Conninfra/WARP, WTS and upstream diagnostics | Manual only; component selector |

## Ownership and safety boundaries

- The OpenSSL 1.1.1w-to-3.5.9 header comparison is optional, non-blocking traceability.
  Quick/Full do not call it or consume its artifact. The target 3.5.9 source inventory,
  target preprocessor evidence and candidate-scope semantic gate own compatibility acceptance.

- The vendor audit is the sole owner of vendor Lock, archive integrity, patch order and
  vendor patch replay evidence. Do not duplicate these checks in another workflow.
- Quick Prepare is the sole reusable no-compile acceptance chain. It retains native OpenWrt
  Package download/unpack/overlay/patch/Build/Prepare behavior.
- Quick and Full must call the same vendor and Prepare workflows in that order.
- Quick and Full firmware build jobs remain hard-frozen with `if: false`. Workflow cleanup
  must never unfreeze either build.
- The 68-item OpenSSL inventory is historical traceability, not a required migration count.
  The 40-item set is a candidate review matrix, not an instruction to migrate every row.
  Actual migration scope must be based on target-source callsites, preprocessing reachability
  and semantic evidence.
- OpenSSL compatibility, vendor-source integrity and Linux kernel patch acceptance remain
  separate technical concerns. Do not create a combined mega-audit.
- Component diagnostics are advisory/on-demand. They do not replace the canonical vendor
  audit or approve firmware builds.
- Preserve run-bound evidence, exact Git SHA, Lock hash, artifact digests and existing
  SHA256 credentials where they remain inputs to a live gate. Do not create parallel
  credentials for the same acceptance decision.
- Keep permissions read-only unless a specific workflow operation demonstrably requires more.
  Pin actions/runtime versions deliberately; do not add unrelated workflow machinery.

## Change rule

Before removing or merging a workflow, identify its callers, outputs and downstream consumers.
Transfer only checks that have a clear existing owner, then verify the resulting YAML,
workflow-call graph, artifact provenance and hard-freeze conditions. Prefer deleting redundant
automation over introducing a replacement meta-workflow.
