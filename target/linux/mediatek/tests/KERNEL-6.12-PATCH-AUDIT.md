# Linux 6.12.112 patch-stack audit

## Purpose

This audit is a pre-build gate for the exact Linux 6.12.112 source archive, the
OpenWrt patch directories and the pre-patch overlays used by the N60 Pro build.
It does not replace the kernel compiler or runtime testing.

## Application order

The inventory follows the native OpenWrt order:

1. `target/linux/generic/backport-6.12`
2. `target/linux/generic/pending-6.12`
3. `target/linux/generic/hack-6.12`
4. `target/linux/mediatek/patches-6.12`

Each directory uses its `series` file when populated; otherwise it uses the
same sorted filename order as the OpenWrt patch helper. Overlay directories are
applied before patches in the order recorded by the inventory.

## Per-patch source audit

During the native `target/linux/prepare` operation, the optional patch wrapper
runs the real GNU `patch` command first. After each successful patch it scans
the files touched by that patch:

- C and header duplicate function definitions;
- repeated or conflicting function prototypes;
- duplicate file-scope struct/union/enum definitions;
- duplicate Device Tree labels;
- mutually exclusive preprocessor/Device Tree alternatives are distinguished
  from coexisting definitions where the lexical scanner can establish this.

A source finding is recorded without interrupting the remaining patch sequence.
This is deliberate: one run should collect the full diagnostic set. Any
intermediate blocking finding creates an `intermediate-failures` marker and
prevents attestation issuance.

The wrapper also runs targeted contracts after the relevant dependency points:
MT7530 base Netlink patch, MT7530 hardening patch, AN8855 hardening patch and
PCIe Gen3 IRQ-affinity sequence.

## Final source gates

Before issuing an attestation, the workflow runs:

- scanner regression fixtures;
- wrapper regression fixtures, including proof that an intermediate finding
  is recorded while patch application continues;
- whole-tree C/header, Kconfig, Makefile and DTS structural scan;
- MT7530 Netlink lifecycle and bounds checks;
- AN8855 Netlink errno, bounds and procfs lifecycle checks;
- PCIe Gen3 MSI parsing, IRQ rollback, affinity and soft-power lifecycle checks;
- exact patch-log sequence, zero-fuzz, no-reject and no-`.orig` checks.

Attestation schema v3 binds the repository HEAD, pinned kernel archive,
ordered patch and overlay manifests, patch log, whole-tree source report, and
the complete set of per-patch audit report hashes and finding counts.

Quick and Full must verify the same attestation artifact from the same workflow
run. A changed patch, overlay, audit rule or repository revision invalidates
the prior attestation.

## Scope and limitations

The source scanner is lexical and conservative; it is not a C parser, compiler,
Sparse, Coccinelle or a substitute for configuration-aware link analysis.
Cross-file global symbol, macro, Kconfig and Makefile repetitions are reported
as review candidates because the same identifier can be legitimate in
configuration-exclusive kernel code. Same-file conflicting declarations and
coexisting duplicate definitions are blocking findings.

Linux API compatibility still requires component-specific semantic contracts
and comparison against the exact 6.12 headers/source. The current targeted
contracts cover the known DSA and PCIe regressions; they do not claim that all
vendor drivers have been proven API-compatible merely because patch application
or this static audit succeeds.

No Quick or Full compile is authorized until the patch-stack audit and its
immutable attestation pass.
