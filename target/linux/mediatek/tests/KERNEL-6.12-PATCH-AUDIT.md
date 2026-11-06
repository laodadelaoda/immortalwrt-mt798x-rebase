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

## Batch revisions already made

- The duplicate `mt7530_write()` prototype was removed from the MT7530 base
  patch (#02); the later hardening patch (#09) no longer carries a cleanup
  hunk for a defect that the base patch should not introduce.
- PCIe IRQ-affinity patch #02 was regenerated against the reconstructed
  post-#01 Linux 6.12 source from the failed prepare artifact. The three rejected
  areas (IRQ teardown, grouped MSI handler and multi-IRQ setup/rollback) now
  use the actual surrounding source context. The MSI affinity callback also
  validates parent IRQ data and updates effective affinity only on success.
- The regenerated PCIe file diff was applied to the reconstructed pre-#02
  source with zero fuzz and compared byte-for-byte with the intended result.
  This is a targeted patch reconstruction check, not the final full-stack
  verification.

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


## Ethernet/HNAT/PPE/NPU, PHY/WED and TNL API contracts

The next network-offload gate checks the prepared Linux 6.12 source, rather than
grepping patch descriptions. It verifies:

- XFRM lookup and state-release APIs used by PPE, plus the XFRM fields consumed
  by the IPsec rekey path;
- destination/neighbour and route APIs used by L2TP/PPTP tunnel path discovery;
- the patched HNAT, NPU and PPP callback structures in their final headers;
- L2TP dst reference acquisition and transfer, nft route transfer, flow creation
  transfer, and both-direction teardown release;
- PPE XFRM state lookup/put pairing and Ethernet RX callback error/null fallback;
- GRE/VXLAN single-tunnel recursion guards and callback registration.

A missing in-tree assignment to the nullable MediaTek tunnel-offload hooks is
reported for review rather than treated as a Linux API failure: the provider may
be supplied by the separately built WED/WARP vendor component. That external
provider must be audited against the same callback contract before claiming
end-to-end NPU/WED offload compatibility.

The verifier also requires the intermediate per-patch report directory.
An attestation cannot be verified from the whole-tree report alone; every patch
report must be present and hash-match.


## PHY/PCS/WED lifecycle and API contracts

The PHY/WED gate checks the Linux phylink callback signature after the 6.14
backport sequence, the generic PHY API declarations consumed by the MediaTek
PCS drivers, and the final SGMII/USXGMII delayed-work lifecycle. Polling must
start only from PCS enable and must be stopped before synchronous work
cancellation; error paths must release the PCS regmap mutex.

It also checks the WED RX-ring configured flag against the RX ring actually
being freed, and verifies typed MMIO mapping, NULL checks, and unmapping in the
PCIe interrupt-trigger path. These checks cover the identified regressions in
the current patch set; they do not replace a full PHY link negotiation test or
hardware WED DMA/RRO stress test.
