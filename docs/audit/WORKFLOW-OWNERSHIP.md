# N60 Pro workflow ownership freeze

Status: frozen responsibility matrix
Maintenance branch: `n60pro-mtk-closed-driver`
Scope: N60 Pro MT798x / ImmortalWrt 25.12 / Linux 6.12 / OpenSSL 3.5.9

This file is the authoritative ownership boundary for the 7 retained GitHub Actions workflows.
A workflow may be changed or removed only when its owned checks, evidence, triggers, and callers
have been transferred and verified. Do not add a new workflow for a check that belongs to an
existing owner. Do not weaken a gate to make a workflow pass.

## Canonical gate chain

1. `vendor-source-patch-audit.yml` is the sole reusable fixed-vendor archive, Lock, patch-order,
   zero-fuzz replay, source-integrity, native package Prepare, and MT Wi-Fi 026 evidence gate.
   It emits the run-bound vendor attestation consumed by downstream workflows.
2. `quick-prepare-audit.yml` is reusable-only. It verifies the same-run vendor attestation,
   retrieves the successful OpenSSL 68-item baseline for the exact Git SHA, validates the
   baseline artifact ID/digest/run/attempt, and performs native Prepare plus OpenSSL target/API,
   kernel patch-stack, and source regression gates. It does not compile firmware.
3. `easymesh-quick.yml` calls the two canonical gates in order and permits Quick only after both
   succeed. Its source build uses the shared composite action.
4. `main.yml` calls the same two canonical gates in the same order. Full build remains frozen
   with `if: false`; no workflow cleanup may unfreeze it.

## Frozen 7-workflow responsibility matrix

| Workflow | Sole responsibility | Trigger / invocation |
|---|---|---|
| `vendor-source-patch-audit.yml` | Canonical fixed-vendor Lock/archive/patch/native Prepare + MT Wi-Fi 026 audit; emits vendor attestation | reusable, manual, dedicated documentation trigger |
| `quick-prepare-audit.yml` | Reusable no-compile Prepare and OpenSSL/kernel acceptance gates | workflow_call only |
| `easymesh-quick.yml` | Quick entry; requires vendor then Prepare gates | manual only (automatic trigger disabled while firmware compilation is frozen) |
| `main.yml` | Full entry; requires vendor then Prepare gates; build remains frozen | manual only |
| `openssl-migration-baseline-audit.yml` | Single OpenSSL audit owner: 68-item header/API traceability plus target-preprocessor and 40-API gate positive/negative regression suite | every maintenance-branch push, path-filtered PR, manual |
| `component-source-diagnostics.yml` | Consolidated WAPP/DPP, Conninfra/WARP, WTS, and upstream delta/closed-component compatibility diagnostics; preserves the upstream report, same-run vendor attestation, and 90-day evidence artifact | manual only; choose one component, upstream, or all |
| `workflow-governance-audit.yml` | YAML/trigger/call graph/permissions/attestation/cache governance checks | workflow/action/governance-script path changes |

## Non-duplication rules

- Component source diagnostics are on-demand jobs inside one workflow, not independent automatic
  approval gates. Upstream mode explicitly calls the canonical vendor audit as a prerequisite; its
  impact report verifies the same-run attestation and remains advisory rather than firmware approval.
- The 68-item OpenSSL baseline is traceability evidence, not the active 40-item migration verdict.
  Its exact-SHA attestation is an input to Quick Prepare, not a replacement for the 40-item gate.
  Baseline runs for superseded commits are cancelled; the latest branch SHA retains its own credential.
- OpenSSL parser, reachability, and fail-closed positive/negative regressions live inside the
  canonical OpenSSL workflow. They are tests of the audit implementation, not approval of API
  migrations; the 40-row semantic review remains the sole migration decision record.
- Upstream compatibility is an upstream selector in component diagnostics. It reuses the canonical
  vendor audit, binds its report to the same-run attestation, and cannot approve a changed vendor Lock,
  patch stack, closed-binary ABI, device runtime, or firmware build.
- Governance validates the fixed workflow set. A new workflow is a governance failure until this
  matrix and its attestation/caller relationships are deliberately revised.
- Quick and Full must call the exact same reusable vendor and Prepare workflows in that order.
  Both must download and remotely verify the same final 40-API OpenSSL credential format, binding
  the exact Git SHA, run/attempt, vendor Lock, source hashes, and evidence artifact digest. Quick's
  automatic push trigger is disabled while firmware compilation remains frozen.
- Never use a cross-run vendor attestation. The OpenSSL baseline is intentionally cross-workflow
  because it is a separate exact-SHA workflow; Quick Prepare verifies its Git SHA, successful
  run identity, artifact ID, and GitHub artifact digest before consuming it.
- Full remains frozen until independent Linux 6.12 DSA/MT7530/Netlink and related kernel patch
  audits are explicitly cleared.

## Change control

Before changing this matrix:
1. identify the current owner and every caller/artifact consumer;
2. move checks and evidence without reducing coverage;
3. update the governance assertions and vendor attestation input inventory;
4. add negative tests for missing, stale, cross-SHA, cross-run, or bypassed evidence;
5. validate the governance, exact-SHA baseline, vendor audit, and Prepare chain on one commit;
6. retain reports, source contexts, artifact digests, and SHA256 credentials.

No additional audit workflow, generic wrapper, or duplicate approval gate should be introduced
unless an existing workflow cannot own the check without violating a clear isolation boundary.
